package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"io"
	"math/big"
	mathrand "math/rand"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

func randomASCII(minlength int, maxlength int) string {
	mathrand.Seed(time.Now().UnixNano())
	chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz" +
		"0123456789" +
		"-+!<#$%>&()?*")
	var length int
	if minlength == maxlength {
		length = minlength
	} else {
		length = mathrand.Intn(maxlength-minlength) + minlength
	}
	var b strings.Builder
	for i := 0; i < length; i++ {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		b.WriteRune(chars[num.Int64()])
	}
	return b.String()
}

func initializeDB(db *sql.DB) {
	_, createerr := db.Exec(`CREATE TABLE IF NOT EXISTS Users (
		id serial PRIMARY KEY,
		name text,
		password text,
		salt text,
		superuser boolean DEFAULT FALSE
	  );`)
	if createerr != nil {
		panic(createerr.Error())
	}

	_, createerr = db.Exec(`CREATE TABLE IF NOT EXISTS Keys (
		user_id integer,
		org_id integer,
		key text,
		salt text,
		nonce text
	  );`)
	if createerr != nil {
		panic(createerr.Error())
	}

	_, createerr = db.Exec(`CREATE TABLE IF NOT EXISTS Organizations (
		id serial PRIMARY KEY,
		name text,
		admin_id integer,
		pub_key text
	  );`)
	if createerr != nil {
		panic(createerr.Error())
	}

	_, createerr = db.Exec(`CREATE TABLE IF NOT EXISTS Cases (
		id BIGSERIAL PRIMARY KEY,
		name text,
		organization_id integer,
		timeutc text
	  );`)
	if createerr != nil {
		panic(createerr.Error())
	}
}

func addUser(db *sql.DB, name string, pass string, superuser bool) int {
	salt := make([]byte, 32)
	io.ReadFull(rand.Reader, salt)

	var id int
	query := db.QueryRow(`INSERT INTO Users (name, password, salt, superuser) VALUES ($1, $2, $3, $4) RETURNING id`,
		name, hex.EncodeToString(argon2.IDKey([]byte(pass), salt, 1, 64*1024, 4, 64)), hex.EncodeToString(salt), superuser)
	query.Scan(&id)

	return id
}

func addKeys(db *sql.DB, adminID int, adminPass string, orgID int) {
	salt := make([]byte, 32)
	io.ReadFull(rand.Reader, salt)

	nonce := make([]byte, 12)
	io.ReadFull(rand.Reader, nonce)
	pubKey, privKey, _ := box.GenerateKey(rand.Reader)
	block, _ := aes.NewCipher(argon2.IDKey([]byte(adminPass), salt, 1, 64*1024, 4, 32))
	aesgcm, _ := cipher.NewGCM(block)
	_, err := db.Exec(`UPDATE Organizations SET pub_key=$1 WHERE id=$2`, hex.EncodeToString(pubKey[:]), orgID)
	if err != nil {
		panic(err.Error())
	}

	_, err1 := db.Exec(`INSERT INTO Keys (user_id, org_id, key, salt, nonce) VALUES ($1, $2, $3, $4, $5)`, adminID, orgID, hex.EncodeToString(aesgcm.Seal(nil, nonce, privKey[:], nil)), hex.EncodeToString(salt), hex.EncodeToString(nonce))
	if err1 != nil {
		panic(err1.Error())
	}

	/*row := db.QueryRow(`SELECT key, salt, nonce FROM Keys WHERE user_id=$1`, adminID)
	var key string
	var salted string
	var nonced string
	row.Scan(&key, &salted, &nonced)
	keyByte, _ := hex.DecodeString(key)
	saltBytes, _ := hex.DecodeString(salted)
	nonceBytes, _ := hex.DecodeString(nonced)

	blocker, _ := aes.NewCipher(argon2.IDKey([]byte(adminPass), saltBytes, 1, 64*1024, 4, 32))

	aesgcmer, _ := cipher.NewGCM(blocker)

	plaintext, _ := aesgcmer.Open(nil, nonceBytes, keyByte, nil)

	fmt.Println(hex.EncodeToString(plaintext))
	fmt.Println(hex.EncodeToString(privKey[:])) Debugging code commented out */
}

func addOrganization(db *sql.DB, orgName string, adminName string, adminPass string) {
	adminID := addUser(db, adminName, adminPass, false)

	var orgID int
	req := db.QueryRow(`INSERT INTO Organizations (name, admin_id) VALUES ($1, $2) RETURNING id`, orgName, adminID)

	req.Scan(&orgID)
	addKeys(db, adminID, adminPass, orgID)
}

func addSuperuser(db *sql.DB) (name string, password string) {
	user := randomASCII(10, 16)
	pass := randomASCII(10, 24)

	_, createerr := db.Exec(`DELETE FROM Users WHERE superuser=true`)
	if createerr != nil {
		panic(createerr.Error())
	}

	addUser(db, user, pass, true)

	return user, pass
}

func encrypt(pubKey *[32]byte, msg []byte) []byte {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}
	var dsk [32]byte

	return box.Seal(nonce[:], msg, &nonce, pubKey, &dsk)
}

func decrypt(privKey *[32]byte, encrypted []byte) []byte {
	var dsk [32]byte
	var dpk [32]byte
	curve25519.ScalarBaseMult(&dpk, &dsk)

	var decryptNonce [24]byte
	copy(decryptNonce[:], encrypted[:24])
	decrypted, ok := box.Open(nil, encrypted[24:], &decryptNonce, &dpk, privKey)
	if !ok {
		panic("Decryption error.")
	}
	return decrypted
}
