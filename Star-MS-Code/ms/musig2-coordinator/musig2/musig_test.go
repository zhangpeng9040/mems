package musig2

import (
	"flag"
	"fmt"
	"testing"
	"time"

	"github.com/360EntSecGroup-Skylar/excelize/v2"
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
	col := flag.Args()[0]
	// 结果写入文件
	f, err1 := excelize.OpenFile("result.xlsx")
	if err1 != nil {
		fmt.Println(err1)
	}

	signersNum := 4000
	noncesNum := 4

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
	wf := int64(comTime / time.Duration(signersNum))
	f.SetCellValue("Sheet1", col+"1", float64(wf)/1000.0)
	var Rvalues []kyber.Point // R_1,...,R_v

	L := ComputeL(pubKeys...)
	X := ComputeX(L, pubKeys...)
	t3 := time.Now()
	for j := 0; j < noncesNum; j++ {
		Rj := curve.Point().Null()
		for i := 0; i < len(publicNonces); i++ {
			Rj = curve.Point().Add(publicNonces[i][j], Rj)
		}
		Rvalues = append(Rvalues, Rj)
	}

	R := ComputeR(msg, Rvalues, X)
	t4 := time.Now()

	fmt.Printf("聚合R和公钥的时间: %v\n", t4.Sub(t3))
	wf = int64(t4.Sub(t3))
	f.SetCellValue("Sheet1", col+"2", float64(wf)/1000.0)
	var sigs []kyber.Scalar
	tt1 := time.Now()
	for _, s := range signers {
		sigs = append(sigs, SignMulti(msg, s.Key, s.Nonces, R, Rvalues, X, L))
	}
	tt2 := time.Now()
	fmt.Printf("部分签名时间: %v\n", tt2.Sub(tt1)/time.Duration(signersNum))
	wf = int64(tt2.Sub(tt1) / time.Duration(signersNum))
	f.SetCellValue("Sheet1", col+"3", float64(wf)/1000.0)
	t7 := time.Now()
	S := AggregateSignatures(sigs...)
	t8 := time.Now()
	sig := &Signature{
		R: R,
		S: S,
	}
	fmt.Printf("累加部分签名的时间: %v\n", t8.Sub(t7))
	wf = int64(t8.Sub(t7))
	f.SetCellValue("Sheet1", col+"4", float64(wf)/1000.0)
	err := f.Save()
	if err != nil {
		fmt.Println(err)
	}
	assert.True(t, VerifySignature(msg, sig, pubKeys...))
}
