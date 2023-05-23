package dwms

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3"
)

type Signer struct {
	Key    *Key
	Nonces []*Key
}

// 创建签名者，产生其密钥和随机数向量
func createSigner(noncesNum int) Signer {
	var nonces []*Key
	t1 := time.Now()
	for j := 0; j < noncesNum; j++ {
		nonce := NewKey()
		nonces = append(nonces, nonce)
	}
	t2 := time.Now()
	comTime += t2.Sub(t1)
	return Signer{
		Key:    NewKey(),
		Nonces: nonces,
	}
}

var comTime time.Duration = 0
var ResTime time.Duration = 0

func TestManySigners(t *testing.T) {
	msg := []byte("MuSig2")

	signersNum := 500 
	noncesNum := 2

	var signers []Signer

	var pubKeys []kyber.Point
	var publicNonces [][]kyber.Point // R_11,...,R_1v,...,R_n1,...,R_nv
	for i := 0; i < signersNum; i++ {
		signer := createSigner(noncesNum) //创建签名者
		signers = append(signers, signer) // 加入签名者集合
		pubKeys = append(pubKeys, signer.Key.Pub) // 公钥集合	
		var pubNonces []kyber.Point // R_i1,...,R_iv
		// first round
		for _, nonce := range signer.Nonces {
			pubNonces = append(pubNonces, nonce.Pub)
		}
		publicNonces = append(publicNonces, pubNonces)
	}
	fmt.Printf("一个签名者产生承诺值的时间: %v\n", comTime/time.Duration(signersNum)) 
	L := ComputeL(pubKeys...)
	X := ComputeX(L, pubKeys...)
	
	t3 := time.Now()
	R := ComputeT(msg, X, publicNonces)
	t4 := time.Now()
	fmt.Printf("聚合R时间: %v\n", t4.Sub(t3))
	var sigs []kyber.Scalar
	tt1 := time.Now()
	for i, s := range signers {
		sigs = append(sigs, SignMulti(uint64(i), msg, s.Key, s.Nonces, R, publicNonces, X, L))
	}
	tt2 := time.Now()
	fmt.Printf("部分签名时间: %v\n", tt2.Sub(tt1)/time.Duration(signersNum))
	t7 := time.Now()
	sig := &Signature{
		R: R,
		S: AggregateSignatures(sigs...),
	}
	t8 := time.Now()
	fmt.Printf("累加部分签名的时间: %v\n", t8.Sub(t7))
	assert.True(t,  VerifySignature(msg, sig, pubKeys...))
}
