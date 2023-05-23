package dwms

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
func SignMulti(i uint64, msg []byte, key *Key, nonces []*Key, R kyber.Point, T_ij [][]kyber.Point, X kyber.Point, L []byte) kyber.Scalar {
	c := computeC(X, R, msg)
	a := computeA(L, key.Pub)
	ax := curve.Scalar().Mul(a, key.Priv)
	axc := curve.Scalar().Mul(c, ax)
	sum := curve.Scalar()
	
	for j, n := range nonces {
		b := computeAlpha(i, uint64(j), msg, T_ij, X)
		sum = curve.Scalar().Add(sum, curve.Scalar().Mul(b, n.Priv))
	}
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

// 计算承诺值 T=T_1 + T_2 + T_3 + ... + T_n
func ComputeT(msg []byte, X kyber.Point, T_ij [][]kyber.Point) kyber.Point {
	T := curve.Point().Null()
	for i, ts := range T_ij {
		Tu := curve.Point().Null()
		for j, t := range ts {
			alpha := computeAlpha(uint64(i), uint64(j), msg, T_ij, X)
			Tu = curve.Point().Add(Tu, curve.Point().Mul(alpha, t))
		}
		T = curve.Point().Add(T, Tu)
	}
	return T
}

// 计算承诺值系数alpha_ij
func computeAlpha(i, j uint64, msg []byte, nonces [][]kyber.Point, X kyber.Point) kyber.Scalar {
	
	var bBytes []byte

	// encode j
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b,i)
	binary.BigEndian.PutUint64(b, j)

	
	bBytes = append(bBytes, encodePoint(X)...)
	for _, ns := range nonces {
		for _, n := range ns {
			bBytes = append(bBytes, encodePoint(n)...)
		}
	}
	bBytes = append(bBytes, msg...)
	bBytes = append(bBytes, b...)
	return curve.Scalar().SetBytes(bBytes)
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
