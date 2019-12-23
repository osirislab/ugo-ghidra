package main

import (
	"fmt"
)

func main() {
	lotsOfParams(1, 2, 3)
	a, b := lotsOfParams(2, 3, 4)

	fmt.Println(a)
	fmt.Println(b)
}

func lotsOfParams(a, b, c int) (int, int) {
	fmt.Println(a)
	fmt.Println(b)
	fmt.Println(c)

	return 2, 3
}
