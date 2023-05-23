package mbcj

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
	Key       *Key
	Nonces    []kyber.Scalar
	PubNonces []kyber.Point
}

// 创建签名者，产生其密钥和随机数向量
func createSigner(param []kyber.Point) Signer {
	t1 := time.Now()
	pubNonces, nonces := GenCom(param)
	t2 := time.Now()
	comTime += t2.Sub(t1)
	return Signer{
		Key:       NewKey(),
		Nonces:    nonces,
		PubNonces: pubNonces,
	}
}

var comTime time.Duration = 0
var ResTime time.Duration = 0

func TestManySigners(t *testing.T) {

	col := flag.Args()[0]

	msg := []byte("It is a good day")
	
	f, err1 := excelize.OpenFile("result.xlsx")
	if err1 != nil {
		fmt.Println(err1)
	}

	signersNum := 500

	param := ComputeH2(msg)
	var signers []Signer

	var pubKeys []kyber.Point
	var publicNonces [][]kyber.Point // t_11,t_12,...,t_n1,t_n2
	var alpha1 []kyber.Scalar
	var alpha2 []kyber.Scalar
	for i := 0; i < signersNum; i++ {
		signer := createSigner(param)     //创建签名者
		signers = append(signers, signer) // 加入签名者集合

		pubKeys = append(pubKeys, signer.Key.Pub) // 公钥集合
		alpha1 = append(alpha1, signer.Nonces[1])
		alpha2 = append(alpha2, signer.Nonces[2])
		publicNonces = append(publicNonces, signer.PubNonces)
	}
	fmt.Printf("一个签名者产生承诺值的时间: %v\n", comTime/time.Duration(signersNum))
	wf := int64(comTime / time.Duration(signersNum))
	f.SetCellValue("Sheet1", col+"1", float64(wf)/1000.0)

	X := ComputeX(pubKeys...)
	// t3 := time.Now()
	R1, R2, t3 := ComputeR(publicNonces)
	// t4 := time.Now()

	fmt.Printf("聚合R的时间: %v\n", t3)
	wf = int64(t3)
	f.SetCellValue("Sheet1", col+"2", float64(wf)/1000.0)
	var sigs []kyber.Scalar
	tt1 := time.Now()
	for _, s := range signers {
		sigs = append(sigs, SignMulti(msg, R1, R2, X, s.Key, s.Nonces))
	}
	tt2 := time.Now()
	fmt.Printf("部分签名时间: %v\n", tt2.Sub(tt1)/time.Duration(signersNum))
	wf = int64(tt2.Sub(tt1) / time.Duration(signersNum))
	f.SetCellValue("Sheet1", col+"3", float64(wf)/1000.0)
	tt3 := time.Now()
	Gama1, Gama2 := ComputeGama(alpha1, alpha2)
	tt4 := time.Now()
	fmt.Printf("累加伽马的时间: %v\n", tt4.Sub(tt3))
	wf = int64(tt4.Sub(tt3))
	f.SetCellValue("Sheet1", col+"4", float64(wf)/1000.0)
	t7 := time.Now()
	S := AggregateSignatures(sigs...)
	t8 := time.Now()
	sig := &Signature{
		R1:    R1,
		R2:    R2,
		S:     S,
		Gama1: Gama1,
		Gama2: Gama2,
	}

	fmt.Printf("累加部分签名的时间: %v\n", t8.Sub(t7))
	wf = int64(t8.Sub(t7))
	f.SetCellValue("Sheet1", col+"5", float64(wf)/1000.0)

	err := f.Save()
	if err != nil {
		fmt.Println(err)
	}
	assert.True(t, VerifySignature(msg, sig, pubKeys...))
}
