package main
import "fmt"

func goroutine(param int) {
    fmt.Println("Hello from goroutine")
    fmt.Println(param)
}

func main() {
    go goroutine(1)
}
