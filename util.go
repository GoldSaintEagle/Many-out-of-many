package main

import (
	"encoding/binary"
	"errors"
	"math"
	"math/big"
	"math/rand"
	"time"
)

//计算<a,b>，即计算a,b两个向量的内积
//a是byte数组，b是uint64数组，要求a,b的长度一致
func Inner_Product(a []byte, b []*big.Int) *big.Int {
	sum := big.NewInt(0)
	for key, _ := range a {
		sum = addInP(sum, mulInP(big.NewInt(int64(a[key])), b[key]))
	}
	//return PutInP(sum,curve)
	//fmt.Println(sum)
	return sum
}

//计算a,b两个向量的内积
//a,b是两个*big.Int类型的数组
func Inner_Product_Big(a []*big.Int, b []*big.Int) *big.Int {
	sum := big.NewInt(0)
	for key, _ := range a {
		sum = addInP(sum, mulInP(a[key], b[key]))
	}
	//fmt.Println(sum)
	return sum
}

//计算a,b两个向量的Hadamard乘积
//a,b是两个int64的数组，要求a,b的长度一致
func CalHadamardVector(a []byte, b []uint64) ([]uint64, error) {
	if len(a) != len(b) {
		return nil, errors.New("两个向量长度不相等")
	}
	var c []uint64
	for i := 0; i < len(a); i++ {
		c = append(c, uint64(a[i])*b[i])
	}
	return c, nil
}

//计算a,b两个向量的Hadamard乘积
//a是byte数组,b是*big.Int数组
func Cal_Hadamard_Vector_Big(a []*big.Int, b []*big.Int) []*big.Int {
	var c []*big.Int

	for key, _ := range a {
		//temp := big.NewInt(1)
		//c = append(c, PutInP(temp.Mul(a[key],b[key]),curve))
		c = append(c, mulInP(a[key], b[key]))
	}
	return c
}

//计算两个向量的相加

func CalVectorSum(a []byte) *big.Int {
	sum := big.NewInt(0)
	for key, _ := range a {
		sum = addInP(sum, big.NewInt(int64(a[key])))
	}
	return sum
}

//a,b均是*big.Int数组
func CalVectorAdd(a []*big.Int, b []*big.Int) []*big.Int {
	var c []*big.Int

	for key, _ := range a {
		//temp := big.NewInt(0)
		//c = append(c,PutInP(temp.Add(a[key],b[key]),curve))
		c = append(c, addInP(a[key], b[key]))
	}
	return c
}

//计算两个向量的相加
//a是*big.Int数组，b是byte数组
func CalVectorAddByte(a []*big.Int, b []byte) []*big.Int {
	var c []*big.Int

	for key, _ := range a {
		//temp := big.NewInt(0)
		//c = append(c, PutInP(temp.Add(a[key],big.NewInt(int64(b[key]))),curve))
		c = append(c, addInP(a[key], big.NewInt(int64(b[key]))))
	}
	return c
}

//计算两个向量相减a-b
//a是*big.Int数组，b是byte数组
func CalVectorSubByte(a []*big.Int, b []byte) []*big.Int {
	var c []*big.Int

	for key, _ := range a {
		//temp := big.NewInt(0)
		//c = append(c, PutInP(temp.Sub(a[key],big.NewInt(int64(b[key]))),curve))
		c = append(c, addInP(a[key], negByte(b[key])))
	}
	return c
}

//计算向量的倍乘b*a
//b是系数，a是*big.Int数组
func CalVectorTimes(a []*big.Int, b int64) []*big.Int {
	var c []*big.Int

	for key, _ := range a {
		//temp := big.NewInt(0)
		//c = append(c, PutInP(temp.Mul(a[key],big.NewInt(b)),curve))
		c = append(c, mulInP(a[key], big.NewInt(b)))
	}
	return c
}

//生成范围证明中的a_L
//v是需要承诺的值，n是范围，即v<=2^n-1
func Generate_b_0(k int64, N int64) ([]*big.Int, error) {

	var b_0 []*big.Int

	//Ensure k<=N
	if k > N {
		return nil, errors.New("The secret number should not be bigger than ring set!")
	}

	//generate a zero binary vector
	for j := 0; j < int(N); j++ {
		b_0 = append(b_0, big.NewInt(0))
	}

	//Generate N-length binary vector with k "1"
	var i int64
	var num int64
	for {
		temp := GenerateRandomInt(num)
		index := math.Mod(float64(temp), float64(N))
		if b_0[int(index)].Cmp(big.NewInt(0)) == 0 {
			b_0[int(index)] = big.NewInt(1)
			i++
		}
		if i == k {
			break
		}
		num++
	}
	return b_0, nil
}

// func Big_int_to_bytes(x *big.Int) []byte {
// 	if x.neg == false{
// 		return x.Bytes()
// 	}
// 	if x.neg == true{
// 		return negBig(x).Bytes()
// 	}
// }

//根据a_L,生成a_R
func Generate_b_1(b_0 []*big.Int) (b_1 []*big.Int) {

	for _, value := range b_0 {
		//sub := big.NewInt(0)
		//	if value.Cmp(big.NewInt(0))>0 {
		//		a_R = append(a_R,big.NewInt(0))
		//	}else{
		//a_R = append(a_R,sub.Sub(curve.P,big.NewInt(1)))
		//		a_R = append(a_R,negByte(1))
		//	}
		//a_R = append(a_R,PutInP(value.Sub(a_L[key], big.NewInt(1)),prover.curve))
		b_1 = append(b_1, addInP(value, negByte(1)))
	}
	return b_1
}

//根据底数c和指数n，生成向量c^n
func Generate_Scalar_Vector(y byte, n int64) []*big.Int {
	var yVector []*big.Int
	var i int64 = 1
	yVector = append(yVector, big.NewInt(1))
	for ; i < n; i++ {
		//temp := big.NewInt(1)
		//yVector =append(yVector, PutInP(temp.Mul(yVector[i-1],big.NewInt(int64(y))),curve))
		yVector = append(yVector, mulInP(yVector[i-1], big.NewInt(int64(y))))
	}
	return yVector
}

//生成全为z的向量
func GenerateZ(z byte, n int64) []byte {
	var zVector []byte
	for i := n; i > 0; i-- {
		zVector = append(zVector, z)
	}
	return zVector
}

//Generate random value (byte)
func GenerateRandom(r int) byte {
	seed := time.Now().UnixNano()
	rand.Seed(seed + int64(r))
	//return 1
	return byte(rand.Intn(255))
}

//Generate random vector (byte)
func GenerateRandomVector(n int) []byte {
	seed := time.Now().UnixNano()
	var rand_vector []byte
	for i := 0; i < n; i++ {
		rand.Seed(seed + int64(i))
		rand_vector = append(rand_vector, byte(rand.Intn(255)))
	}
	return rand_vector
}

//生成随机数(int)
func GenerateRandomInt(r int64) int {
	seed := time.Now().UnixNano()
	rand.Seed(seed + r)
	//return 0
	return rand.Int()
}

//生成s_L和s_R随机序列
func GenerateS(n int64, r int) []*big.Int {
	var s []*big.Int
	for i := n; i > 0; i-- {
		seed := time.Now().UnixNano()
		rand.Seed(seed + i + int64(r))
		s = append(s, big.NewInt(int64(rand.Intn(2))))
	}
	return s
}

//生成h的逆元向量
func GenerateH1(H []Point, y byte, n int64) []Point {
	yn := Generate_Scalar_Vector(y, n)
	var h1 []Point
	for key, value := range H {
		var point Point
		point.x, point.y = curve.ScalarMult(value.x, value.y, inverseBig(yn[key]).Bytes())
		h1 = append(h1, point)
	}
	return h1
}

func GenerateZVector(z byte, n int64) []*big.Int {
	var zn []*big.Int
	for i := n; i > 0; i-- {
		zn = append(zn, big.NewInt(int64(z)))
	}
	return zn
}
func GeneratenegZVector(z byte, n int64) []*big.Int {
	var zn []*big.Int
	for i := n; i > 0; i-- {
		zn = append(zn, negBig(big.NewInt(int64(z))))
	}
	return zn
}

func GenerateYn1(y byte, n int64) []*big.Int {
	yn := Generate_Scalar_Vector(y, n)

	var yn1 []*big.Int
	for _, value := range yn {
		temp := big.NewInt(0)
		//sub := big.NewInt(1)
		//temp.ModInverse(value, temp.Sub(curve.P,big.NewInt(1)))
		temp.ModInverse(value, curve.P)
		yn1 = append(yn1, temp)
	}
	return yn1
}

//Int64转byte
func Int64ToBytes(i int64) []byte {
	var buf = make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(i))
	return buf
}

//byte转int64
func BytesToInt64(buf []byte) int64 {
	return int64(binary.BigEndian.Uint64(buf))
}
