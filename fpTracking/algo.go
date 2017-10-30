package fpTracking

import (
	"fmt"
	"sort"
	"time"
	"github.com/texttheater/golang-levenshtein/levenshtein"
)

type fingerprintLocalId struct {
	counter int
	order int
}

type matching struct {
	fp_local_id fingerprintLocalId
	nb_changes int
	user_id string
}

func ruleBased(fingerprint_unknown Fingerprint, user_id_to_fps map[string][]fingerprintLocalId, counter_to_fingerprint map[int]Fingerprint) string{

	/*
        Given an unknown fingerprint fingerprint_unknown,
        and a set of known fingerprints user_id_to_fps and counter_to_fingerprint,
        tries to link fingerprint_unknown to a fingerprint in
        counter_to_fingerprint.
        If it can be linked it returns the id of the fingerprint it has been linked with,
        otherwise it returns a new generated user id.
    */
    
    //forbidden_changes := []string {"canvasJSHashed","localJS","dntJS","cookiesJS"}

    //ip_allowed := false
    //var candidates []matching
    var exact_matching []matching
    //var prediction []string

    for user_id, fp_local_id_list := range user_id_to_fps {
    		for _, fp_local_id := range fp_local_id_list {
    			counter_known := fp_local_id.counter
    			fingerprint_known := counter_to_fingerprint[counter_known]

    			//check fingerprint full hash for exact matching
    			if fingerprint_known.ExactHash == fingerprint_unknown.ExactHash {
    				// either we look if there are multiple users that match
    				// in that case we create new id
    				// or we assign randomly?
    				exact_matching = append(exact_matching,matching{fp_local_id,0,user_id})
    			} else if len(exact_matching) < 1 && fingerprint_known.ConstantHash == fingerprint_unknown.ConstantHash {
    				//we make the comparison only if same os/browser/platform
    				if fingerprint_known.GlobalVersion > fingerprint_unknown.GlobalVersion {
    					continue
    				}
    				
    				if fingerprint_known.HasFlashActivated() && fingerprint_unknown.HasFlashActivated() && !fingerprint_known.AreFontsSubset(fingerprint_unknown) {
    					continue
    				}

    				//Forbidden changes :
    				//We check on CanvasHashed, Local, Dnt and Cookies
    				//CanvasHashed
    				if fingerprint_known.CanvasHashed != fingerprint_unknown.CanvasHashed {
    					continue
    				}
    				//Local
    				if fingerprint_known.Local != fingerprint_unknown.Local {
    					continue
    				}
    				//Dnt
    				if fingerprint_known.Dnt != fingerprint_unknown.Dnt {
    					continue
    				}
    				//Cookies
    				if fingerprint_known.Cookies != fingerprint_unknown.Cookies {
    					continue
    				}

    				//Allowed changes :
    				//We check on UserAgent, Vendor, Renderer, Plugins, Language, Accept
    				nb_changes := 0
    				var changes []string
    				//we allow at most 2 changes, then we check for similarity
    				//UserAgent
    				if nb_changes <= 2 && fingerprint_known.UserAgent != fingerprint_unknown.UserAgent {
    					nb_changes += 1
    					changes = append(changes,"UserAgent")
    				}
    				//Vendor
    				if nb_changes <= 2 && fingerprint_known.Vendor != fingerprint_unknown.Vendor {
    					nb_changes += 1
    					changes = append(changes,"Vendor")
    				}
    				//Renderer
    				if nb_changes <= 2 && fingerprint_known.Renderer != fingerprint_unknown.Renderer {
    					nb_changes += 1
    					changes = append(changes,"Renderer")
    				}
    				//Plugins
    				if nb_changes <= 2 && fingerprint_known.Plugins != fingerprint_unknown.Plugins {
    					nb_changes += 1
    					changes = append(changes,"Plugins")
    				}
    				//Language
    				if nb_changes <= 2 && fingerprint_known.Language != fingerprint_unknown.Language {
    					nb_changes += 1
    					changes = append(changes,"Language")
    				}
    				//Accept
    				if nb_changes <= 2 && fingerprint_known.Accept != fingerprint_unknown.Accept {
    					nb_changes += 1
    					changes = append(changes,"Accept")
    				}
    				if nb_changes > 2 {
    					continue
    				}

    				sim_too_low := false
    				for _,attribute := range changes {
    					//UserAgent
    					if (attribute == "UserAgent" && levenshtein.RatioForStrings([]rune(fingerprint_known.UserAgent),[]rune(fingerprint_unknown.UserAgent),levenshtein.DefaultOptions)<0.75) {
    						sim_too_low = true
    						break
    					}
    					//Vendor
    					if (attribute == "Vendor" && levenshtein.RatioForStrings([]rune(fingerprint_known.Vendor),[]rune(fingerprint_unknown.Vendor),levenshtein.DefaultOptions)<0.75) {
    						sim_too_low = true
    						break
    					}
    					//Renderer
    					if (attribute == "Renderer" && levenshtein.RatioForStrings([]rune(fingerprint_known.Renderer),[]rune(fingerprint_unknown.Renderer),levenshtein.DefaultOptions)<0.75) {
    						sim_too_low = true
    						break
    					}
    					//Plugins
    					if (attribute == "Plugins" && levenshtein.RatioForStrings([]rune(fingerprint_known.Plugins),[]rune(fingerprint_unknown.Plugins),levenshtein.DefaultOptions)<0.75) {
    						sim_too_low = true
    						break
    					}
    					//Language
    					if (attribute == "Language" && levenshtein.RatioForStrings([]rune(fingerprint_known.Language),[]rune(fingerprint_unknown.Language),levenshtein.DefaultOptions)<0.75) {
    						sim_too_low = true
    						break
    					}
    					//Accept
    					if (attribute == "Accept" && levenshtein.RatioForStrings([]rune(fingerprint_known.Accept),[]rune(fingerprint_unknown.Accept),levenshtein.DefaultOptions)<0.75) {
    						sim_too_low = true
    						break
    					}
    				}
    				if sim_too_low {
    					continue
    				}

    			}
    		}
    }

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
