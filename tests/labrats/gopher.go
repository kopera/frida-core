package main

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	_ "net" // needed to make frida work so that binary is dynamically linked
)

func main() {
	busyLoop(context.Background(), new(int))
}

// busyLoop increments a counter via two convoluted recursive functions. The
// goal is to exercise the stack walking code for goroutines which are running.
//
// We use two mutually recursive functions that have different call stack sizes
// to try to ensure that the proper frame pointer is being used. If we had only
// one function or we had recursive functions with one stack depth, then it
// could be possible to walk the stack using the frame pointer from the g and
// still get to a valid stack frame. By randomizing the order of calls of these
// functions with different stack sizes, we make it less likely that we'll find
// in the g struct a frame pointer that still pointers to a valid frame.
//
// Runs until cancelled.
func busyLoop(ctx context.Context, counter *int) int {
	fmt.Println("busyLoop starting") // Synchronize with the test.
	prev := *counter
	ch := make(chan struct{}, 1)
	for {
		select {
		case <-ctx.Done():
			return prev
		default:
			// Pick a skewed random number to determine the depth of the recursion.
			// By using a skewed distribution we ensure that the go runtime won't
			// end up picking a large default stack size and preventing stack growth.
			v := int(math.Pow(rand.ExpFloat64()+1, 5))
			go func() {
				defer func() { ch <- struct{}{} }()
				*counter, prev = recurseA(*counter, int(v), 0), *counter
			}()
			<-ch
		}
	}
}

func recurseA(input int, depth int, another_value int) int {
	if depth == 0 {
		return input + 1 + another_value
	}
	if rand.Intn(2) == 0 {
		return recurseA(input, depth-1, another_value+1)
	} else {
		return recurseB(input, depth-1)
	}
}

func recurseB(input int, depth int) int {
	if depth == 0 {
		return input + 2
	}
	if rand.Intn(2) == 0 {
		return recurseA(input, depth-1, 0)
	} else {
		return recurseB(input, depth-1)
	}
}
