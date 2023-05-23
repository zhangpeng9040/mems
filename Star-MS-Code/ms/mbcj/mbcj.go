package mbcj

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/suites"
)

var curve = suites.MustFind("Ed25519")

// 返回用的群
func Curve() suites.Suite {
	return curve

}

// 签名
type Signature struct {
	R1    kyber.Point
	R2    kyber.Point
	S     kyber.Scalar
	Gama1 kyber.Scalar
	Gama2 kyber.Scalar
}

// 密钥
type Key struct {
	Priv kyber.Scalar
	Pub  kyber.Point
}

// 产一个签名者的部分签名s_i
func SignMulti(msg []byte, t1, t2 kyber.Point, X kyber.Point, key *Key, ra []kyber.Scalar) kyber.Scalar {
	c := computeC(t1, t2, X, msg)
	xc := curve.Scalar().Mul(c, key.Priv)
	sum := curve.Scalar()
	sum = curve.Scalar().Add(sum, ra[0])
	return curve.Scalar().Add(sum, xc)
}

func VerifySignature(msg []byte, sig *Signature, pubKeys ...kyber.Point) bool {
	X := ComputeX(pubKeys...)
	param := ComputeH2(msg)
	t1 := time.Now()
	c := computeC(sig.R1, sig.R2, X, msg)

	proof1 := curve.Point().Add(curve.Point().Mul(sig.Gama1, nil), curve.Point().Mul(sig.Gama2, param[1]))

	temp1 := curve.Point().Add(curve.Point().Mul(sig.Gama1, param[0]), curve.Point().Mul(sig.Gama2, param[2]))
	temp2 := curve.Point().Add(temp1, curve.Point().Mul(sig.S, nil))
	proof2 := curve.Point().Add(sig.R2, curve.Point().Mul(c, X))
	t2 := time.Now()
	fmt.Printf("验证签名时间: %v\n", t2.Sub(t1))
	return proof1.Equal(sig.R1) && temp2.Equal(proof2)
}

// s=s1 + s2 + ··· + sn
func AggregateSignatures(sigs ...kyber.Scalar) kyber.Scalar {
	s := curve.Scalar()
	for _, sig := range sigs {
		s = curve.Scalar().Add(s, sig)
	}
	return s
}

// 计算承诺值 t1, t2
func ComputeR(pubNonces [][]kyber.Point) (kyber.Point, kyber.Point, int64) {
	t1 := curve.Point().Null()
	t2 := curve.Point().Null()
	var tt int64 = 0

	for _, n := range pubNonces {
		tt1 := time.Now()
		t1 = curve.Point().Add(t1, n[0])
		t2 = curve.Point().Add(t2, n[1])
		tt2 := time.Now()
		tt += int64(tt2.Sub(tt1))
	}

	return t1, t2, tt
}

// 计算挑战值
func computeC(t1, t2, X kyber.Point, msg []byte) kyber.Scalar {
	h := sha256.Sum256(append(encodePoint(t1), append(encodePoint(t2), append(encodePoint(X), msg...)...)...))
	return curve.Scalar().SetBytes(h[:])
}

// compute PK X=X_1 * X_2 * ... * X_n
func ComputeX(pubKeys ...kyber.Point) kyber.Point {
	X := curve.Point().Null()
	for _, p := range pubKeys {
		X = curve.Point().Add(X, p)
	}

	return X
}

// compute Gama1, Gama2
func ComputeGama(alpha1, alpha2 []kyber.Scalar) (kyber.Scalar, kyber.Scalar) {
	Y1 := curve.Scalar()
	Y2 := curve.Scalar()
	for i := range alpha1 {
		Y1 = curve.Scalar().Add(Y1, alpha1[i])
		Y2 = curve.Scalar().Add(Y2, alpha2[i])
	}
	return Y1, Y2
}

// 返回一对新的密钥
func NewKey() *Key {
	x := curve.Scalar().Pick(curve.RandomStream())
	P := curve.Point().Mul(x, curve.Point().Base())

	return &Key{
		Priv: x,
		Pub:  P,
	}
}

func ComputeH2(msg []byte) []kyber.Point {
	temp := make([]byte, 8)
	res := make([]kyber.Point, 3)
	for i := 1; i < 4; i++ {
		binary.BigEndian.PutUint64(temp, uint64(i))
		bs := sha256.Sum256(append(msg, temp...))
		res[i-1] = curve.Point().Mul(curve.Scalar().SetBytes(bs[:]), nil)
	}
	return res
}

// 产生承诺值
func GenCom(param []kyber.Point) ([]kyber.Point, []kyber.Scalar) {
	ra := make([]kyber.Scalar, 3)
	res := make([]kyber.Point, 2)
	for i := 0; i < 3; i++ {
		ra[i] = curve.Scalar().Pick(curve.RandomStream())
	}
	g1alpha := curve.Point().Mul(ra[1], nil)
	h1alpha := curve.Point().Mul(ra[2], param[1])
	res[0] = curve.Point().Add(g1alpha, h1alpha)

	g2alpha := curve.Point().Mul(ra[1], param[0])
	h2alpha := curve.Point().Mul(ra[2], param[2])
	g1r := curve.Point().Mul(ra[0], nil)
	res[1] = curve.Point().Add(curve.Point().Add(g2alpha, h2alpha), g1r)

	return res, ra
}

func encodePoint(p kyber.Point) []byte {
	b, _ := p.MarshalBinary()
	return b
}
