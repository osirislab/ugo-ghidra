package main

import "fmt"

func dummy() {
    fmt.Println("Dummy printing")

    defer func() {
        fmt.Println("Dummy deferred")
    }()

    fmt.Println("Dummy finished deferring")
}
func main() {
    dummy()
}
