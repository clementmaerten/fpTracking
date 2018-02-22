# fpTracking

This repository contains a Golang library for the algorithms which can track a fingerprint over the time. These algorithms were developped by the Spirals Team of the INRIA in Lille.

## Getting Started
### Prerequisites

To use this library, you'll have to install some libraries :

```
 github.com/xrash/smetrics
 github.com/satori/go.uuid
 github.com/avct/uasurfer
 gopkg.in/oleiade/reflections.v1
```

There is a Makefile in this package in order to install these libraries.

### Installing

To download and use this package, follow the instructions below :

 * Get the repository
```
 $ go get github.com/clementmaerten/fpTracking
```

 * Go inside this directory
```
 $ cd $(go env GOPATH)/src/github.com/clementmaerten/fpTracking
```

 * Then execute the Makefile (it will download the required libraries and install the package)
```
 $ make
```

Here is an example of a small program which reads into the database some fingerprints and tries to link them (here the database is mysql so it needs github.com/go-sql-driver/mysql in order to work) :

```Go
package main

import (
	"os"
	"fmt"
	"strconv"
	"time"
	"github.com/clementmaerten/fpTracking"
	_ "github.com/go-sql-driver/mysql"
)

func main() {
	
	if len(os.Args) != 3 {
		fmt.Println("There is not 2 parameters !")
		os.Exit(1)
	}

	number, err1 := strconv.Atoi(os.Args[1])
	train, err2 := strconv.ParseFloat(os.Args[2],64)
	if (err1 != nil || err2 != nil) {
		fmt.Println("The format is not respected !")
		os.Exit(1)
	}

	if _, errFold := os.Stat("results"); os.IsNotExist(errFold) {
		os.Mkdir("results", 0700)
	}

	fingerprintManager := fpTracking.FingerprintManager{
		Number: number,
		Train:  train,
		MinNumberFpPerUser: 6,
		DBInfo: fpTracking.DBInformation {
			DBType: "mysql",
			User: "root",
			Password: "passwd",
			TCP: "",
			DBName: "fingerprint",
		},
	}

	beginTime := time.Now()

	fmt.Printf("Start fetching fingerprints\n")
	_, test := fingerprintManager.GetFingerprints()
	fmt.Printf("Fetched %d fingerprints\n", len(test))
	visitFrequencies := []int{1, 2, 3, 4, 5, 6, 7, 8, 10, 15, 20}
	expName := "testrule1"
	for _, visitFrequency := range visitFrequencies {
		fmt.Println("Visit frequency :",visitFrequency)

		fileName1 := fmt.Sprintf("./results/%s_%d-res1.csv", expName, visitFrequency)
		fileName2 := fmt.Sprintf("./results/%s_%d-res2.csv", expName, visitFrequency)
		
		scenarioResult := fpTracking.ReplayScenario(test, visitFrequency, fpTracking.RuleBasedLinking)
		fpTracking.AnalyseScenarioResultInFiles(scenarioResult, test, fileName1, fileName2)

	}

	fmt.Println("Total time :",time.Since(beginTime).Seconds(),"seconds")
}

```
