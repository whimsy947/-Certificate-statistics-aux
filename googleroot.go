package main

import (
	"bufio"
	"fmt"
	"github.com/gocolly/colly"
	"log"
	"os"
	"strings"
)

var addressurl = "https://ccadb.my.salesforce-sites.com/microsoft/IncludedCACertificateReportForMSFT"

var count int

func getsha() {

	c := colly.NewCollector(
		colly.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36"),
		colly.AllowURLRevisit(),
	)
	//#mainbody > div > div > table > tbody > tr:nth-child(1) > td:nth-child(5) > a
	//设置gbk和重复访问
	//_ = c.SetProxy("http://127.0.0.1:7890") // 设置代理
	//+ 表示选择紧随其前的同级元素，也就是选择相邻的元素
	catalogselector := "#mainbody > div > div > table > tbody > tr:contains('Included')>td:contains('Secure Email')"
	c.OnHTML(catalogselector, func(elem *colly.HTMLElement) {
		// Find all td elements containing "Secure Email"
		count++
		fmt.Printf("Total number of Secure Email: %d\n", count)
	})

	//data := []byte(elem.Text)
	//err := ioutil.WriteFile("macossha256.txt", data, 0666)
	//if err != nil {
	//	log.Fatal(err)
	//}

	c.Visit(addressurl)
}
func tidy() {
	file, err := os.Open("./win.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// 逐行读取并去除空格
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.ReplaceAll(line, " ", "")
		fmt.Println(line)
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}
func main() {
	getsha()
	//tidy()

}
