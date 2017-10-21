package fpTracking

import (
	"fmt"
	"sort"
	"time"
)

func ruleBased(fingerprint_unknown Fingerprint, user_id_to_fps map[string][]int, counter_to_fingerprint map[int]Fingerprint) string{

	/*
        Given an unknown fingerprint fingerprint_unknown,
        and a set of known fingerprints user_id_to_fps and counter_to_fingerprint,
        tries to link fingerprint_unknown to a fingerprint in
        counter_to_fingerprint.
        If it can be linked it returns the id of the fingerprint it has been linked with,
        otherwise it returns a new generated user id.
    */
    
    forbidden_changes := []string {"canvasJSHashed","localJS","dntJS","cookiesJS"}

    ip_allowed := false

    for user_id, counter_str_list := range user_id_to_fps {
    		for _, counter_str := range counter_str_list {

    		}
    }

    var prediction []string

	//A CHANGER ENSUITE
	return "abcd_efgh_ijkl_mnop"
}

type ScenarioResult struct {
	counterStr string
	assignedID string
}

type sequenceElt struct {
	counterStr string
	counter    int
	lastVisit  time.Time
}

func generateReplaySequence(fingerprintDataset []Fingerprint, visitFrequency int) []sequenceElt {
	userIDToFingerprints := make(map[string][]Fingerprint)
	for _, fingerprint := range fingerprintDataset {
		userIDToFingerprints[fingerprint.UserID] = append(userIDToFingerprints[fingerprint.UserID], fingerprint)
	}
	userIDToSequence := make(map[string][]sequenceElt)

	for userID := range userIDToFingerprints {
		// fmt.Printf("user id: %s\n", userID)
		if len(userIDToFingerprints[userID]) > 1 {
			sequence := make([]sequenceElt, 0)
			lastVisit := userIDToFingerprints[userID][0].CreationDate
			counterSuffix := "i"
			assignedCounter := fmt.Sprintf("%d_%s", userIDToFingerprints[userID][0].Counter, counterSuffix)
			// fmt.Printf("assignedCounter %s\n", assignedCounter)
			sequence = append(sequence, sequenceElt{counterStr: assignedCounter,
				lastVisit: lastVisit,
				counter:   userIDToFingerprints[userID][0].Counter})

			for i := 0; i < len(userIDToFingerprints[userID])-1; i++ {
				fingerprint := userIDToFingerprints[userID][i]
				counterSuffixInt := 0

				for lastVisit.AddDate(0, 0, visitFrequency).Sub(fingerprint.EndDate) < 0 {
					lastVisit = lastVisit.AddDate(0, 0, visitFrequency)
					assignedCounter = fmt.Sprintf("%d_%d", fingerprint.Counter, counterSuffixInt)
					// fmt.Printf("assignedCounter %s\n", assignedCounter)
					sequence = append(sequence, sequenceElt{counterStr: assignedCounter,
						lastVisit: lastVisit,
						counter:   fingerprint.Counter})
					counterSuffixInt++
				}
			}
			userIDToSequence[userID] = sequence
		}
	}

	replaySequence := make([]sequenceElt, 0)
	for _, sequences := range userIDToSequence {
		for _, sequence := range sequences {
			replaySequence = append(replaySequence, sequence)
		}
	}

	// for _, sequence := range replaySequence {
	// fmt.Printf("rep seq: %s", sequence.counterStr)
	// }

	sort.Slice(replaySequence, func(i, j int) bool {
		return replaySequence[i].lastVisit.Sub(replaySequence[j].lastVisit) < 0
	})

	return replaySequence
}


//Function replay_scenario :
