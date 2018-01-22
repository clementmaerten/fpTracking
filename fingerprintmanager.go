package fpTracking

import (
	"os"
	"database/sql"
	"bufio"
	"strings"
	"log"
	"time"
	"math"
)

// Information for connection to the database
type DBInformation struct {
	DBType, User, Password, TCP, DBName string
}

// FingerprintManager manages the obtention of fingerprints
type FingerprintManager struct {
	Number int
	Train  float64
	MinNumberFpPerUser int
	DBInfo DBInformation
}

// GetFingerprints returns two slices train, test of Fingerprint structs
func (fm FingerprintManager) GetFingerprints() ([]Fingerprint, []Fingerprint) {
	db, _ := sql.Open(fm.DBInfo.DBType,
		fm.DBInfo.User+":"+fm.DBInfo.Password+"@"+fm.DBInfo.TCP+"/"+fm.DBInfo.DBName+"?parseTime=true")
	defer db.Close()

	file, _ := os.Open("./data/consistent_extension_ids.csv")
	defer file.Close()

	scanner := bufio.NewScanner(file)
	consistentIDs := []string{"'"}
	for scanner.Scan() {
		consistentIDs = append(consistentIDs, scanner.Text())
	}
	consistentIDs = append(consistentIDs, "'")
	consistentIDsQuery := strings.Join(consistentIDs, "','")


	fingerprints := make([]Fingerprint, 0)
	trainFingerprints := make([]Fingerprint, 0)
	testFingerprints := make([]Fingerprint, 0)

	/*stmt, err := db.Prepare(`SELECT counter, id, addressHttp, creationdate, endDate,
									userAgentHttp, acceptHttp, connectionHttp, 
									encodingHttp, languageHttp, orderHttp,
									pluginsJS, platformJS, cookiesJS, dntJS,
									timezoneJS, resolutionJS, localJS,
									fontsFlash, vendorWebGLJS, rendererWebGLJS,
									pluginsJSHashed, fontsFlashHashed, canvasJSHashed
									FROM extensionData WHERE counter < ? AND
									creationDate IS NOT NULL AND
									endDate IS NOT NULL AND char_length(id) > 15
									AND id in (` + consistentIDsQuery + `) AND id in
									(SELECT id FROM extensionData group by id having count(*) > 6) order by counter`)
	*/

	stmt, err := db.Prepare(`SELECT counter, id, addressHttp, creationdate, endDate,
									userAgentHttp, acceptHttp, connectionHttp, 
									encodingHttp, languageHttp, orderHttp,
									pluginsJS, platformJS, cookiesJS, dntJS,
									timezoneJS, resolutionJS, localJS,
									fontsFlash, vendorWebGLJS, rendererWebGLJS,
									pluginsJSHashed, fontsFlashHashed, canvasJSHashed
									FROM extensionData WHERE counter < ? AND
									creationDate IS NOT NULL AND
									endDate IS NOT NULL AND char_length(id) > 15
									AND id in (` + consistentIDsQuery + `) AND id in
									(SELECT id FROM extensionData where counter < ? group by id having count(*) > ?) order by counter`)

	if err != nil {
		panic(err.Error()) // proper error handling instead of panic in your app
	}
	defer stmt.Close()

	rows, err := stmt.Query(fm.Number, fm.Number, fm.MinNumberFpPerUser)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var counter int
	var id, addressHTTP, userAgentHTTP, acceptHTTP, connectionHTTP string
	var encodingHTTP, languageHTTP, orderHTTP, pluginsJS, platformJS string
	var cookiesJS, dntJS, timezoneJS, resolutionsJS, localJS, fontsFlash string
	var vendor, renderer, pluginsJSHashed, fontsFlashHashed, canvasJSHashed string
	var creationDate, endDate time.Time

	cpt := 0
	var nbTrain, nbTest int
	for rows.Next() {
		err := rows.Scan(&counter, &id, &addressHTTP, &creationDate, &endDate, &userAgentHTTP,
			&acceptHTTP, &connectionHTTP, &encodingHTTP, &languageHTTP, &orderHTTP, &pluginsJS,
			&platformJS, &cookiesJS, &dntJS, &timezoneJS, &resolutionsJS, &localJS,
			&fontsFlash, &vendor, &renderer, &pluginsJSHashed, &fontsFlashHashed, &canvasJSHashed)

		if err != nil {
			log.Fatal(err)
		}

		fp := Fingerprint{
			Counter:       counter,
			UserID:        id,
			AddressHTTP:   addressHTTP,
			CreationDate:  creationDate,
			EndDate:       endDate,
			UserAgent:     userAgentHTTP,
			Accept:        acceptHTTP,
			Connection:    connectionHTTP,
			Encoding:      encodingHTTP,
			Language:      languageHTTP,
			Order:         orderHTTP,
			Plugins:       pluginsJS,
			Platform:      platformJS,
			Cookies:       cookiesJS,
			Dnt:           dntJS,
			Timezone:      timezoneJS,
			Resolution:    resolutionsJS,
			Local:         localJS,
			FontsFlash:    fontsFlash,
			Vendor:        vendor,
			Renderer:      renderer,
			PluginsHashed: pluginsJSHashed,
			FontsHashed:   fontsFlashHashed}

		fp.InitFingerprint()

		fingerprints = append(fingerprints, fp)
		cpt++

	}

	nbTrain = int(math.Ceil(fm.Train * float64(cpt)))
	nbTest = cpt - nbTest

	for i := 0; i < nbTrain; i++ {
		trainFingerprints = append(trainFingerprints, fingerprints[i])
	}

	for i := nbTrain; i < cpt; i++ {
		testFingerprints = append(testFingerprints, fingerprints[i])
	}

	return trainFingerprints, testFingerprints
}
