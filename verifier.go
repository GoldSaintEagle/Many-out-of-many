package main

import (
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v3"
)

type Verifier struct {
	//公开的参数，包括G,H和G,H的矢量，要承诺的范围n,以及相同的椭圆曲线
	Public_g, U, V     Point
	P_Vector, H_Vector []Point
	N                  int64
	curve              *secp256k1.KoblitzCurve

	//prover发送的承诺A,S
	A, B, C, D Point

	//发给prover的随机数y,z
	y, z, d byte

	//prover发送的承诺T1,T2
	T1, T2 Point

	//发送给prover的随机数c
	c byte

	//承诺P
	P Point

	//和矢量h相关的h`
	HH_Vector []Point

	//零知识证明阶段Prover发送的相关的变量
	proverZKP ProverZKP
}

func (verifier *Verifier) New(Public_g Point, U Point, V Point, H_Vector []Point, N int64, curve secp256k1.KoblitzCurve) {
	verifier.Public_g = Public_g
	verifier.U = U
	verifier.V = V
	verifier.H_Vector = H_Vector[:N]
	verifier.N = N
	verifier.curve = &curve
	//verifier.y = 0
	verifier.y = GenerateRandom(1)
	verifier.z = GenerateRandom(2)
	//verifier.d = 1
	verifier.d = GenerateRandom(3)
	fmt.Println("challenge:", verifier.y, verifier.z, verifier.d)
}

func (verifier *Verifier) Input_Com(A Point, B Point, C Point, D Point, P_Vector []Point) {
	verifier.A = A
	verifier.B = B
	verifier.C = C
	verifier.D = D
	verifier.P_Vector = P_Vector
}

func (verifier *Verifier) Input_T(T1 Point, T2 Point) {
	verifier.T1 = T1
	verifier.T2 = T2
}

func (verifier *Verifier) GenerateX() {
	verifier.c = GenerateRandom(0)
}

func (verifier *Verifier) VerifyZKP() bool {
	if !verifier.verify_Tx() {
		fmt.Println("Failed Verification of Commitments T1, T2 !")
		return false
	}
	fmt.Println("Verification of Commitments T1, T2 Succeeded !")

	if !verifier.verify_ABC() {
		fmt.Println("Failed verification of Commitments A, B, C !")
		return false
	}
	fmt.Println("Verification of Commitments A, B, C Succeeded !")

	if !verifier.verify_Secret() {
		fmt.Println("Failed verification of Commitments D (secrets) !")
		return false
	}
	fmt.Println("Verification of Commitments D Succeeded !")

	if !verifier.verify_IP() {
		fmt.Println("Failed verification of Inner-product Relation !")
		return false
	}
	fmt.Println("Verification of Commitments Inner-product Relation Succeeded !")
	return true
}

//验证t(x)
func (verifier *Verifier) verify_Tx() bool {
	c2 := big.NewInt(1)
	z2 := big.NewInt(1)
	c2.Mul(big.NewInt(int64(verifier.c)), big.NewInt(int64(verifier.c)))
	z2.Mul(big.NewInt(int64(verifier.z)), big.NewInt(int64(verifier.z)))

	//left equation
	commit_L := Commit(verifier.V, verifier.U, verifier.proverZKP.tx, verifier.proverZKP.taux)

	//right equation
	commit_V_delta := CommitSingle(verifier.V, verifier.Caculate_Delta())
	commit_T1_T2 := Commit(verifier.T1, verifier.T2, big.NewInt(int64(verifier.c)), c2)
	commit_R := MultiCommit(commit_T1_T2, commit_V_delta)
	return IsEqual(commit_L, commit_R)
}

//根据y,z，计算δ(x,y)
func (verifier *Verifier) Caculate_Delta() *big.Int {
	delta := big.NewInt(1)
	z2 := big.NewInt(1)
	Vector_y_N := Generate_Scalar_Vector(verifier.y, verifier.N)
	z2 = mulInP(big.NewInt(int64(verifier.z)), big.NewInt(int64(verifier.z)))
	delta_0 := Inner_Product(GenerateZ(1, verifier.N), CalVectorTimes(Vector_y_N, int64(verifier.d)))
	z1_z2 := addInP(big.NewInt(int64(verifier.z)), negBig(z2))
	delta = mulInP(delta_0, z1_z2)
	//fmt.Println("delta",negBig(delta))
	return delta
}

//生成承诺P
func (verifier *Verifier) Caculate_ABC() {
	//neg := big.NewInt(0)

	A := verifier.A
	B := verifier.B
	C := verifier.C
	h1 := GenerateH1(verifier.H_Vector, verifier.y, verifier.N)
	verifier.HH_Vector = h1
	commitAB := Commit(A, B, big.NewInt(1), big.NewInt(int64(verifier.d)))
	commitC := CommitSingle(C, big.NewInt(int64(verifier.c)))
	//commitZ := CommitSingle(verifier.G, negByte(verifier.z).Bytes())
	//todo
	commitZ := CommitSingleVector(verifier.P_Vector, GeneratenegZVector(verifier.z, verifier.N))
	commitPoly := CommitSingleVector(verifier.H_Vector, CalVectorTimes(GenerateZVector(verifier.z, verifier.N), int64(verifier.d)))
	commitABC := MultiCommit(commitAB, commitC)
	verifier.P = MultiCommit(commitABC, MultiCommit(commitZ, commitPoly))
}

//Verify A,B,C
func (verifier *Verifier) verify_ABC() bool {
	verifier.Caculate_ABC()
	commitLR := CommitVectors(verifier.P_Vector, verifier.HH_Vector, verifier.proverZKP.eta, verifier.proverZKP.zeta)
	commitMju := CommitSingle(verifier.U, verifier.proverZKP.mju)
	P1 := MultiCommit(commitLR, commitMju)
	return IsEqual(verifier.P, P1)
}

//验证承诺secret
func (verifier *Verifier) verify_Secret() bool {
	commit_g_f := CommitSingle(verifier.Public_g, verifier.proverZKP.f_s)
	commit_u_f := CommitSingle(verifier.U, verifier.proverZKP.f_alpha)
	commit_L := MultiCommit(commit_g_f, commit_u_f)
	commit_R := MultiCommit(CommitSingle(verifier.A, big.NewInt(int64(verifier.c))), verifier.D)
	return IsEqual(commit_L, commit_R)
}

//验证lx和rx是否相等
func (verifier *Verifier) verify_IP() bool {
	lx := verifier.proverZKP.eta
	rx := verifier.proverZKP.zeta
	tx := Inner_Product_Big(lx, rx)
	return tx.Cmp(verifier.proverZKP.tx) == 0
}
