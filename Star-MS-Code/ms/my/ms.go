package ms

import (
	"crypto/sha256"
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
	R kyber.Point
	S kyber.Scalar
}

// 密钥
type Key struct {
	Priv kyber.Scalar
	Pub  kyber.Point
}

// 对签名进行编码
func (s *Signature) Encode() []byte {
	return append(encodePoint(s.R), encodeScalar(s.S)...)
}

// 解码得到签名
func DecodeSignature(sig []byte) (*Signature, error) {
	p := curve.Point()
	err := p.UnmarshalBinary(sig[:32])
	if err != nil {
		return nil, err
	}
	s := curve.Scalar().SetBytes(sig[32:])
	return &Signature{
		R: p,
		S: s,
	}, nil
}

// 产一个签名者的部分签名s_i
func SignMulti(msg []byte, key , nonce *Key, w kyber.Scalar, R kyber.Point, X kyber.Point, L []byte) kyber.Scalar {
	c := computeC(X, R, msg)
	a := computeA(L, key.Pub)
	ax := curve.Scalar().Mul(a, key.Priv)
	axc := curve.Scalar().Mul(c, ax)
	sum := curve.Scalar()
	// w+r_i
	sum = curve.Scalar().Add(sum, curve.Scalar().Add(w, nonce.Priv))
	// w+r_i+ca_ix_i
	return curve.Scalar().Add(sum, axc)
}

func VerifySignature(msg []byte, sig *Signature, pubKeys ...kyber.Point) bool {
	L := ComputeL(pubKeys...)
	X := ComputeX(L, pubKeys...)
	t1 := time.Now()
	c := computeC(X, sig.R, msg)

	proof := curve.Point().Add(X.Mul(c, X), sig.R)
	sG := curve.Point().Mul(sig.S, curve.Point().Base())
	t2 := time.Now()
	fmt.Printf("验证签名时间: %v\n", t2.Sub(t1))

	return proof.Equal(sG)
}

// s=s1 + s2 + ··· + sn
func AggregateSignatures(sigs ...kyber.Scalar) kyber.Scalar {
	s := curve.Scalar()
	for _, sig := range sigs {
		s = curve.Scalar().Add(s, sig)
	}
	return s
}

// 计算承诺值
func ComputeR(Nonces []kyber.Point, Gw kyber.Point) kyber.Point {
	R := curve.Point().Null()
	for _, n := range Nonces {
		temp := curve.Point().Add(n, Gw)
		R = curve.Point().Add(R, temp)
	}
	return R
}

// 计算公钥系数a_i
func computeA(L []byte, X kyber.Point) kyber.Scalar {
	p, _ := X.MarshalBinary()
	hash := sha256.Sum256(append(L, p...))
	return curve.Scalar().SetBytes(hash[:])
}

// 计算挑战值
func computeC(X, R kyber.Point, msg []byte) kyber.Scalar {
	h := sha256.Sum256(append(encodePoint(X), append(encodePoint(R), msg...)...))
	return curve.Scalar().SetBytes(h[:])
}

// 计算聚合公钥
func ComputeX(L []byte, pubKeys ...kyber.Point) kyber.Point {
	X := curve.Point().Null()

	for _, p := range pubKeys {
		ap := curve.Point().Mul(computeA(L, p), p)
		X = curve.Point().Add(X, ap)
	}

	return X
}

// 计算公钥集合的哈希
func ComputeL(pubKeys ...kyber.Point) []byte {
	var data []byte
	for _, p := range pubKeys {
		b, _ := p.MarshalBinary()
		data = append(data, b...)
	}

	h := sha256.Sum256(data)
	return h[:]
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

func encodePoint(p kyber.Point) []byte {
	b, _ := p.MarshalBinary()
	return b
}
func encodeScalar(s kyber.Scalar) []byte {
	b, _ := s.MarshalBinary()
	return b
}
