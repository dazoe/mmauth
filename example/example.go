package main

import (
	"encoding/json"
	"fmt"
	"mmauth"
	"os"
	"time"
)

func main() {
	msoToken := new(mmauth.MSOToken)
	if _, err := os.Stat("msoToken.json"); os.IsNotExist(err) {
		msoToken, err = mmauth.MSOAuth("")
		if err != nil {
			panic(err)
		}
		buf, err := json.Marshal(msoToken)
		if err != nil {
			panic(err)
		}
		if err := os.WriteFile("msoToken.json", buf, 0644); err != nil {
			panic(err)
		}
	} else {
		fmt.Println("using saved msoToken")
		f, err := os.Open("msoToken.json")
		if err != nil {
			panic(err)
		}
		if err := json.NewDecoder(f).Decode(msoToken); err != nil {
			panic(err)
		}
		if msoToken.Expired() {
			fmt.Println("  refreshing")
			if err := msoToken.Refresh(); err != nil {
				panic(err)
			}
			buf, err := json.Marshal(msoToken)
			if err != nil {
				panic(err)
			}
			if err := os.WriteFile("msoToken.json", buf, 0644); err != nil {
				panic(err)
			}
		}
	}

	fmt.Printf("Expired: %t\n", time.Now().After(msoToken.Expires))
	fmt.Printf("Expires in: %s\n", msoToken.Expires.Sub(time.Now()).String())

	mcProfile, err := mmauth.GetMCProfile(msoToken)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%#+v\n", mcProfile)
}
