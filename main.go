package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func compare() {
	file1, err := os.Open("./win.txt")
	if err != nil {
		panic(err)
	}
	defer file1.Close()

	hash1 := make(map[string]bool)
	scanner := bufio.NewScanner(file1)
	for scanner.Scan() {
		hash1[scanner.Text()] = true
	}

	file2, err := os.Open("./Motlssha256.txt")
	if err != nil {
		panic(err)
	}
	defer file2.Close()

	var count int
	scanner = bufio.NewScanner(file2)
	for scanner.Scan() {
		if hash1[scanner.Text()] {
			count++
		}
	}

	fmt.Printf("There are %d matching hash values.", count)
}
func tidy() {
	file, err := os.Open("win.txt")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	output, err := os.Create("win_no_blank.txt")
	if err != nil {
		panic(err)
	}
	defer output.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {

		line := strings.TrimSpace(scanner.Text())

		if line != "" {

			_, err := fmt.Fprintf(output, "%s\n", line)
			if err != nil {
				panic(err)
			}
		}
	}
}
func main() {
	compare()
	//tidy()
}
