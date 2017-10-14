package main

import (
	"fmt"
	
	
	_ "github.com/go-sql-driver/mysql"
)

func main() {
	fingerprintManager := fpTracking.FingerprintManager{
		Number: 30000,
		Train:  0.4}

	fmt.Printf("Start fetching fingerprints\n")
	_, test := fingerprintManager.GetFingerprints()
	fmt.Printf("Fetched %d fingerprints\n", len(test))
	visitFrequencies := []int{1, 2, 3, 4, 5, 6, 7, 8, 10, 15, 20}
	expName := "testrule1"
	for _, visitFrequency := range visitFrequencies {
		fileName1 := fmt.Sprintf("./results/%s_%d-res1.csv", expName, visitFrequency)
		fileName2 := fmt.Sprintf("./results/%s_%d-res2.csv", expName, visitFrequency)
		scenarioResult := fpTracking.ReplayScenario(fpTracking.RuleBasedLinking, test, visitFrequency)
		fpTracking.AnalyseScenarioResult(scenarioResult, test,
			fileName1, fileName2)
	}
}
