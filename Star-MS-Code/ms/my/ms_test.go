package ms

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"go.dedis.ch/kyber/v3"
)

type Signer struct {
	Key    *Key
	Nonces *Key
	Gw     *Key
}

// 创建签名者，产生其密钥和随机数向量
func createSigner() Signer {
	t1 := time.Now()
	nonce := NewKey()
	t2 := time.Now()
	comTime += t2.Sub(t1)
	return Signer{
		Key:    NewKey(),
		Nonces: nonce,
	}
}

var comTime time.Duration = 0
var ResTime time.Duration = 0

func TestManySigners(t *testing.T) {

	msg := []byte("It is a good day")

	signersNum := 4000

	var signers []Signer

	var pubKeys []kyber.Point
	var publicNonces []kyber.Point // R_11,...,R_1v,...,R_n1,...,R_nv
	for i := 0; i < signersNum; i++ {
		signer := createSigner()          //创建签名者
		signers = append(signers, signer) // 加入签名者集合

		pubKeys = append(pubKeys, signer.Key.Pub) // 公钥集合

		publicNonces = append(publicNonces, signer.Nonces.Pub)
	}
	fmt.Printf("一个签名者产生承诺值的时间: %v\n", comTime/time.Duration(signersNum))

	temp := make([]byte, 8)
	curTime := time.Now()
	binary.BigEndian.PutUint64(temp, uint64(curTime.UnixNano()))
	timestamp := sha256.Sum256(temp)
	w := curve.Scalar().SetBytes(timestamp[:])
	Gw := curve.Point().Mul(w, nil)
	L := ComputeL(pubKeys...)
	X := ComputeX(L, pubKeys...)

	t3 := time.Now()
	R := ComputeR(publicNonces, Gw)
	t4 := time.Now()

	fmt.Printf("聚合R: %v\n", t4.Sub(t3))

	var sigs []kyber.Scalar
	tt1 := time.Now()
	for _, s := range signers {
		sigs = append(sigs, SignMulti(msg, s.Key, s.Nonces, w, R, X, L))
	}
	tt2 := time.Now()
	fmt.Printf("部分签名时间: %v\n", tt2.Sub(tt1)/time.Duration(signersNum))

	t7 := time.Now()
	S := AggregateSignatures(sigs...)
	t8 := time.Now()
	sig := &Signature{
		R: R,
		S: S,
	}
	fmt.Printf("累加部分签名的时间: %v\n", t8.Sub(t7))
	assert.True(t, VerifySignature(msg, sig, pubKeys...))
}
