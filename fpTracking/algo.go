package fpTracking

import (
	"fmt"
	"sort"
	"time"
	"github.com/texttheater/golang-levenshtein/levenshtein"
	"gopkg.in/oleiade/reflections.v1"
	"github.com/satori/go.uuid"
)

type fingerprintLocalId struct {
	counter int
	order string
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
    
    forbidden_changes := []string {"CanvasHashed","Local","Dnt","Cookies"}
    allowed_changes_with_sim := []string{"UserAgent","Vendor","Renderer","Plugins","Language","Accept"}
    allowed_changes := []string{"Resolution","Encoding","Timezone"}

    ip_allowed := false
    var candidates []matching
    var exact_matching []matching
    var prediction string

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
				//We check all attributes in forbidden_changes
				forbidden_change_found := false
				for _,attribute := range forbidden_changes {
					value_known, err1 := reflections.GetField(fingerprint_known,attribute)
					value_unknown, err2 := reflections.GetField(fingerprint_unknown,attribute)
					if err1 != nil || err2 != nil {
						fmt.Printf("Erreur dans les attributs de forbidden_changes\n")
					} else {
						if value_known != value_unknown {
							forbidden_change_found = true
							break
						}
					}
				}
				if forbidden_change_found {
					continue
				}

				//Allowed changes :
				//We check all attributes in allowed_changes_with_sim
				nb_changes := 0
				var changes []string
				//we allow at most 2 changes, then we check for similarity
				for _,attribute := range allowed_changes_with_sim {
					value_known, err1 := reflections.GetField(fingerprint_known,attribute)
					value_unknown, err2 := reflections.GetField(fingerprint_unknown,attribute)
					if err1 != nil || err2 != nil {
						fmt.Printf("Erreur dans les attributs de allowed_changes_with_sim\n")
					} else {
						if value_known != value_unknown {
							changes = append(changes,attribute)
							nb_changes += 1
						}
					}

					if nb_changes > 2 {
						break
					}
				}
				if nb_changes > 2 {
					continue
				}

				sim_too_low := false
				for _,attribute := range changes {
					value_known, err1 := reflections.GetField(fingerprint_known,attribute)
					value_unknown, err2 := reflections.GetField(fingerprint_unknown,attribute)
					if err1 != nil || err2 != nil {
						fmt.Printf("Erreur dans les attributs de changes\n")
					} else {
						if levenshtein.RatioForStrings([]rune(value_known.(string)),[]rune(value_unknown.(string)),levenshtein.DefaultOptions) < 0.75 {
							sim_too_low = true
							break
						}
					}
				}
				if sim_too_low {
					continue
				}

				nb_allowed_changes := 0
				for _,attribute := range allowed_changes {
					value_known, err1 := reflections.GetField(fingerprint_known,attribute)
					value_unknown, err2 := reflections.GetField(fingerprint_unknown,attribute)
					if err1 != nil || err2 != nil {
						fmt.Printf("Erreur dans les attributs de allowed_changes\n")
					} else {
						if value_known != value_unknown {
							nb_allowed_changes += 1
						}
					}

					if nb_allowed_changes > 1 {
						break
					}
				}
				if nb_allowed_changes > 1 {
					continue
				}

				total_nb_changes := nb_allowed_changes + nb_changes
				if total_nb_changes == 0 {
					exact_matching = append(exact_matching,matching{fp_local_id,0,user_id})
				} else {
					candidates = append(candidates,matching{fp_local_id,total_nb_changes,user_id})
				}
			}
		}
    }
    if len(exact_matching) > 0 {
    	if len(exact_matching) == 1 || candidates_have_same_id(exact_matching) {
    		return exact_matching[0].user_id
    	} else if ip_allowed {
    		//We look if same IP address
    		for _,elt := range exact_matching {
    			counter_known := elt.fp_local_id.counter
    			fingerprint_known := counter_to_fingerprint[counter_known]

    			if fingerprint_known.AddressHTTP == fingerprint_unknown.AddressHTTP {
    				prediction = elt.user_id
    				break
    			}
    		}
    	}
    } else {
    	if len(candidates) == 1 || candidates_have_same_id(candidates) {
    		prediction = candidates[0].user_id
    	} else if ip_allowed {
    		//first pass with ip address
    		for _,elt := range candidates {
    			counter_known := elt.fp_local_id.counter
    			fingerprint_known := counter_to_fingerprint[counter_known]

    			if fingerprint_known.AddressHTTP == fingerprint_unknown.AddressHTTP {
    				prediction = elt.user_id
    				break
    			}
    		}
    	}
    }

    if prediction == "" {
    	prediction = generate_new_id()
    }

	return prediction
}

func candidates_have_same_id(candidate_list []matching) bool {
	//Returns True if all candidates have the same id
	//Else False
	length := len(candidate_list)
	if length == 0 {
		return false
	} else if length == 1{
		return true
	} else {
		first_user_id := candidate_list[0].user_id
		all_the_same := true
		for i:=1;i<length;i++ {
			if candidate_list[i].user_id != first_user_id {
				all_the_same = false
				break
			}
		}
		return all_the_same
	}
}

func generate_new_id() string {
	return fmt.Sprintf("%s",uuid.NewV4())
}

type ScenarioResult struct {
	counterStr string
	assignedID string
}

type sequenceElt struct {
	fp_local_id fingerprintLocalId
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
			assignedCounter := fingerprintLocalId{counter: userIDToFingerprints[userID][0].Counter,
				order: counterSuffix}
			sequence = append(sequence, sequenceElt{fp_local_id: assignedCounter,
				lastVisit: lastVisit})

			for i := 0; i < len(userIDToFingerprints[userID])-1; i++ {
				fingerprint := userIDToFingerprints[userID][i]
				counterSuffixInt := 0

				for lastVisit.AddDate(0, 0, visitFrequency).Sub(fingerprint.EndDate) < 0 {
					lastVisit = lastVisit.AddDate(0, 0, visitFrequency)
					counterSuffixString := fmt.Sprintf("%d",counterSuffixInt)
					assignedCounter = fingerprintLocalId{counter: fingerprint.Counter, order: counterSuffixString}
					sequence = append(sequence, sequenceElt{fp_local_id: assignedCounter,
						lastVisit: lastVisit})
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

func ReplayScenario (fingerprintDataset []Fingerprint, visitFrequency int, linkFingerprint func(Fingerprint, map[string][]fingerprintLocalId, map[int]Fingerprint) string) []Fingerprint {

	/*
		Takes as input the fingerprint dataset,
        the frequency of visit in days,
        link_fingerprint, the function used for the linking strategy
        filename, path to the file to save results of the scenario
	*/

	nb_max_cmp := 2
	replaySequence := generateReplaySequence(fingerprintDataset,visitFrequency)
	counter_to_fingerprint := make(map[int]Fingerprint)
	for _,fingerprint := range fingerprintDataset {
		counter_to_fingerprint[fingerprint.Counter] = fingerprint
	}

	var fps_available []Fingerprint //Set of know fingerprints
	user_id_to_fps := make(map[string]Fingerprint)
	counter_to_time := make(map[fingerprintLocalId]time.Time)

	for index, elt := range replaySequence {
		if index % 500 == 0 {
			fmt.Println("index : ",index)
		}

		//ATTENTION au type de l'indexeur de la map !!!
		counter_to_time[elt.fp_local_id] = elt.lastVisit
	}

	//JE NE SUIS PAS ENCORE SUR DU TYPE DE RETOUR DE LA FONCTION
	return fps_available
}