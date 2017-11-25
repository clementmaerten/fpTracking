# fpTracking

This repository contains a golang library for the algorithms which can track a fingerprint over the time. These algorithms were developped by the Spirals Team of the INRIA in Lille.

## Getting Started
### Prerequisites

To use this library, you'll have to install some packages :

```
 $ go get github.com/texttheater/golang-levenshtein/levenshtein
 $ go get github.com/satori/go.uuid
 $ go get github.com/avct/uasurfer
 $ go get gopkg.in/oleiade/reflections.v1
```

### Installing

For now, as the repository is private, **go get** function to get this package won't work. So here are the steps in order to install it :

 * Create the github.com/clementmaerten directory inside your go workspace
```
 $ mkdir -p $(go env GOPATH)/src/github.com/clementmaerten
```

 * Go inside this directory
```
 $ cd $(go env GOPATH)/src/github.com/clementmaerten
```

 * Then clone the repository
```
 $ git clone https://github.com/clementmaerten/fpTracking.git
 or
 $ git clone git@github.com:clementmaerten/fpTracking.git
```

 * Then install the library
```
 $ go install github.com/clementmaerten/fpTracking
```

Here is an example of a small program which reads into the database some fingerprints and tries to link them (here the database is mysql so it needs github.com/go-sql-driver/mysql in order to work) :

```Go
package main

import (
	"os"
	"fmt"
	"strconv"
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
	if (err1 != nil || err2 != nil || train < 0 || train > 1) {
		fmt.Println("The format is not respected !")
		os.Exit(1)
	}

	fingerprintManager := fpTracking.FingerprintManager{
		Number: number,
		Train:  train,
		DBInfo: fpTracking.DBInformation {
			DBType: "mysql",
			User: "root",
			Password: "passwd",
			TCP: "",
			DBName: "fingerprint",
		},
	}

	fmt.Printf("Start fetching fingerprints\n")
	_, test := fingerprintManager.GetFingerprints()
	fmt.Printf("Fetched %d fingerprints\n", len(test))
	visitFrequencies := []int{1, 2, 3, 4, 5, 6, 7, 8, 10, 15, 20}
	expName := "testrule1"
	for _, visitFrequency := range visitFrequencies {
		fileName1 := fmt.Sprintf("./results/%s_%d-res1.csv", expName, visitFrequency)
		fileName2 := fmt.Sprintf("./results/%s_%d-res2.csv", expName, visitFrequency)
		scenarioResult := fpTracking.ReplayScenario(test, visitFrequency, fpTracking.RuleBasedLinking)
		fpTracking.AnalyseScenarioResult(scenarioResult, test, fileName1, fileName2)
	}
}
```
