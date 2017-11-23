package main

import (
	"os"
	"fmt"
	//"reflect"
	"strconv"
	//"log"
	"fpTracking"
	//"database/sql"
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

	fingerprintManager := fpTracking.FingerprintManager{
		Number: number,
		Train:  train}

	fmt.Printf("Start fetching fingerprints\n")
	_, test := fingerprintManager.GetFingerprints()
	fmt.Printf("Fetched %d fingerprints\n", len(test))
	visitFrequencies := []int{1, 2, 3, 4, 5, 6, 7, 8, 10, 15, 20}
	expName := "testrule1"
	for _, visitFrequency := range visitFrequencies {
		fileName1 := fmt.Sprintf("./results/%s_%d-res1.csv", expName, visitFrequency)
		//fmt.Println("fileName 1 : ",fileName1)
		fileName2 := fmt.Sprintf("./results/%s_%d-res2.csv", expName, visitFrequency)
		//fmt.Println("fileName 2 : ",fileName2)
		scenarioResult := fpTracking.ReplayScenario(test, visitFrequency, fpTracking.RuleBasedLinking)
		//fmt.Printf("visitFrequency : %d, length of fps_available : %d\n",visitFrequency,len(scenarioResult))
		//fpTracking.PrintScenarioResult(scenarioResult)
		fpTracking.AnalyseScenarioResult(scenarioResult, test, fileName1, fileName2)
	}

	/* Test connexion BDD

	nb_parameters := os.Args[1]
	
	db, err := sql.Open("mysql", "root:mysql@/fingerprint")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	var (
		counter int
		userId string
	)
	
	rows, err := db.Query("select counter, id from extensionData limit ?",nb_parameters)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&counter, &userId)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("id : %d, userId : %s\n",counter, userId)
	}
	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}*/



	/* Test StringSet
	set := fpTracking.NewStringSet()
	set.Add("test1")
	set.Add("test2")
	set.Add("test3")
	set.Add("test2")
	fmt.Println("len : ",set.Length())
	fmt.Println("set : ",set) 
	fmt.Println(set.Get("test2")) //true
	fmt.Println("set : ",set)
	fmt.Println(set.Get("test4")) //false
	fmt.Println("set : ",set)
	set.Remove("test2")
	fmt.Println(set.Get("test2")) //false
	fmt.Println("set : ",set)
	fmt.Println("len : ",set.Length())

	mp := make(map[string]*fpTracking.StringSet)
	mp["test"] = set
	fmt.Println("PRINT")
	for str,strset := range mp {
		fmt.Println("str : ",str)
		fmt.Println("strset : ",strset)
	}
	fmt.Println("type : ",reflect.TypeOf(mp["test"]))
	mp["test"].Add("bonjour")
	for str,strset := range mp {
		fmt.Println("str : ",str)
		fmt.Println("strset : ",strset)
		fmt.Println("len : ",strset.Length())
	}
	*/

}
