package main

import (
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v3"
)

var prover Prover
var verifier Verifier

func main() {

	setup(4, 16) // k=4 for secret number N = 16 for ring size
	zkpConstruct()
	zkp()
	isInRange := zkpVerify()
	fmt.Println("Verification result:", isInRange)
	//test()
}

func setup(k int64, N int64) {

	curve = secp256k1.S256() //Choose an elliptic curve

	u := GeneratePoint()
	fmt.Println("u = ", u)
	v := GeneratePoint()
	fmt.Println("v = ", v)
	Public_g := GeneratePoint()
	fmt.Println("Public g = ", v)

	h_Vector := GenerateMultiPoint(N)
	fmt.Println("vector h = ", h_Vector)

	//construct an object prover
	err := prover.New(Public_g, u, v, h_Vector, k, N, *curve)
	if err != nil {
		fmt.Println(err)
		return
	}
	//construct an object verifier
	verifier.New(Public_g, u, v, h_Vector, N, *curve)

	//Prover compute Commitments A, B, C, D and transmit to verifier
	A, B, C, D, Public_key := prover.Output_Com()
	fmt.Println("A = ", A, "B = ", B, "C = ", C, "D = ", D)
	verifier.Input_Com(A, B, C, D, Public_key)
	//verifier.GetCom(A, S)

	//verifier get A, B, C, D and transmit y, z, d to prover
	prover.y = verifier.y
	prover.z = verifier.z
	prover.d = verifier.d
	fmt.Println("y = ", prover.y, "z = ", prover.z, "d = ", prover.d)
}

func zkpConstruct() {

	//Prover compute Commitments T1, T2 and transmit to verifier
	T1, T2 := prover.Output_T()
	verifier.Input_T(T1, T2)
	fmt.Println("T1 = ", T1, "T2 = ", T2)

	//verifier get T1, T2 and transmit c to prover
	verifier.GenerateX()
	prover.c = verifier.c
	fmt.Println("c = ", prover.c)
}

func zkp() {
	proverZKP := prover.Output_ProverZKP()
	verifier.proverZKP = proverZKP
	fmt.Println("ZKP = ", verifier.proverZKP)
}

func zkpVerify() bool {
	return verifier.VerifyZKP()
}

// func test() {
// 	tx := negBig(big.NewInt(11))
// 	taux := big.NewInt(0)
// 	delta := negBig(big.NewInt(31))
// 	x0 := negBig(big.NewInt(11))
// 	x1 := big.NewInt(20)
// 	x2 := negBig(big.NewInt(31))

// 	commit2 := CommitSingle(prover.H, x0.Bytes())
// 	commit3 := Commit(prover.H, prover.H, x1.Bytes(), x2.Bytes())

// 	V := Commit(prover.G, prover.H, big.NewInt(prover.v).Bytes(), big.NewInt(int64(prover.gamma)).Bytes())
// 	commit0 := Commit(prover.G, prover.H, tx.Bytes(), taux.Bytes())
// 	commit1 := Commit(V, prover.G, big.NewInt(1).Bytes(), delta.Bytes())

// 	fmt.Println(IsEqual(commit0, commit1))
// 	fmt.Println(IsEqual(commit2, commit3))

// }
