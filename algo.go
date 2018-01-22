package fpTracking

import (
	"fmt"
	"sort"
	"time"
	"os"
	"gopkg.in/oleiade/reflections.v1"
	"github.com/satori/go.uuid"
	"github.com/xrash/smetrics"
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

func RuleBasedLinking(fingerprint_unknown Fingerprint, user_id_to_fps map[string][]fingerprintLocalId, counter_to_fingerprint map[int]Fingerprint) string{

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
						if smetrics.JaroWinkler(value_known.(string), value_unknown.(string), 0.7, 4) < 0.75 {
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
    	if candidates_have_same_id(exact_matching) {
    		return exact_matching[0].user_id
    	}
    } else {
    	if candidates_have_same_id(candidates) {
    		prediction = candidates[0].user_id
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
	gen, _ := uuid.NewV4()
	return fmt.Sprintf("%s",gen)
}

type sequenceElt struct {
	fp_local_id fingerprintLocalId
	lastVisit  time.Time
}

func generateReplaySequence(fingerprintDataset []Fingerprint, visitFrequency int) []sequenceElt {

	/*
		Takes as input a set of fingerprint fingerprintDataset,
		a frequency of visit visit_frequency in days.

		Returns a list of fingerprints in the order they must be replayed
	*/

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

type counter_and_assigned_id struct {
	fp_local_id fingerprintLocalId
	assigned_id string
}

func ReplayScenario (fingerprintDataset []Fingerprint, visitFrequency int, linkFingerprint func(Fingerprint, map[string][]fingerprintLocalId, map[int]Fingerprint) string) []counter_and_assigned_id {

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

	var fps_available []counter_and_assigned_id //Set of know fingerprints (new_counter,assigned_id)
	user_id_to_fps := make(map[string][]fingerprintLocalId)
	counter_to_time := make(map[fingerprintLocalId]time.Time)

	fmt.Println("length : ",len(replaySequence))
	for index, elt := range replaySequence {
		if index % 500 == 0 {
			fmt.Println("index : ",index)
		}

		counter_to_time[elt.fp_local_id] = elt.lastVisit
		counter := elt.fp_local_id.counter
		fingerprint_unknown := counter_to_fingerprint[counter]

		//ATTENTION AU TEST SUR LE MODEL !
		//if model == false
		assigned_id := linkFingerprint(fingerprint_unknown, user_id_to_fps, counter_to_fingerprint)
        
        fps_available = append(fps_available, counter_and_assigned_id{fp_local_id: elt.fp_local_id, assigned_id: assigned_id})
        
        if len(user_id_to_fps[assigned_id]) == nb_max_cmp {
        	//pop the first element
        	user_id_to_fps[assigned_id] = user_id_to_fps[assigned_id][1:]
        }

        user_id_to_fps[assigned_id] = append(user_id_to_fps[assigned_id],elt.fp_local_id)

        //every 2000 elements we delete elements too old
        if index % 2000 == 0 {
        	//30 days in seconds
        	time_limit := float64(30*24*60*60)
        	ids_to_remove := NewStringSet()
        	current_time := elt.lastVisit
        	for user_id,fp_local_id_list := range user_id_to_fps {
        		index_last_element := len(fp_local_id_list)-1
        		if (index_last_element >= 0) {
        			fp_local_id := fp_local_id_list[index_last_element]
        			time_tmp := counter_to_time[fp_local_id]
        			if current_time.Sub(time_tmp).Seconds() > time_limit {
        				ids_to_remove.Add(user_id)
        			}
        		}
        	}
        	for user_id,_ := range ids_to_remove.GetSet() {
        		delete(user_id_to_fps,user_id)
        	}
        }
	}

	return fps_available
}

func PrintScenarioResult(fps_available []counter_and_assigned_id) {
	for index,result := range fps_available {
		fmt.Printf("index : %d, fp_local_id_counter : %d, fp_local_id_order : %s, assigned_id : %s\n",index,result.fp_local_id.counter,result.fp_local_id.order,result.assigned_id)
	}
}

func checkError(e error) {
	if e != nil {
		panic(e)
	}
}

func checkErrorWriting(e error) {
	if e != nil {
		fmt.Printf("error writing string %v",e)
	}
}

func analyseScenarioResult(scenario_result []counter_and_assigned_id, fingerprint_dataset []Fingerprint,
	counter_to_fingerprint map[int]Fingerprint, real_user_id_to_nb_fps map[string]int,
	real_id_to_assigned_ids map[string]*StringSet, assigned_id_to_real_ids map[string]*StringSet,
	assigned_id_to_fingerprints map[string][]Fingerprint) {

	for _,fingerprint := range fingerprint_dataset {
		counter_to_fingerprint[fingerprint.Counter] = fingerprint
	}

	//We map new assigned ids to real ids in database
	for _,elt := range scenario_result {
		counter := elt.fp_local_id.counter
		assigned_id := elt.assigned_id
		real_db_id := counter_to_fingerprint[counter].UserID
		if _,is_present := real_user_id_to_nb_fps[real_db_id]; !is_present {
			real_user_id_to_nb_fps[real_db_id] = 1
		} else {
			real_user_id_to_nb_fps[real_db_id] += 1
		}

		if _,is_present := real_id_to_assigned_ids[real_db_id]; !is_present {
			real_id_to_assigned_ids[real_db_id] = NewStringSet()
		}
		real_id_to_assigned_ids[real_db_id].Add(assigned_id)

		if _,is_present := assigned_id_to_real_ids[assigned_id]; !is_present {
			assigned_id_to_real_ids[assigned_id] = NewStringSet()
		}
		assigned_id_to_real_ids[assigned_id].Add(counter_to_fingerprint[counter].UserID)

		assigned_id_to_fingerprints[assigned_id] = append(assigned_id_to_fingerprints[assigned_id],counter_to_fingerprint[counter])
	}
}

func AnalyseScenarioResultInFiles(scenario_result []counter_and_assigned_id, fingerprint_dataset []Fingerprint, filename1, filename2 string) {
	/*
	   Performs an analysis of a scenario result
	*/

	counter_to_fingerprint := make(map[int]Fingerprint)
	real_user_id_to_nb_fps := make(map[string]int)

	real_id_to_assigned_ids := make(map[string]*StringSet)
	assigned_id_to_real_ids := make(map[string]*StringSet)
	assigned_id_to_fingerprints := make(map[string][]Fingerprint)

	analyseScenarioResult(scenario_result, fingerprint_dataset, counter_to_fingerprint,
		real_user_id_to_nb_fps, real_id_to_assigned_ids, assigned_id_to_real_ids, assigned_id_to_fingerprints)

	//Create and write in the first result file
	f,err := os.Create(filename1)
	checkError(err)
	defer f.Close()
	_,err = f.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s\n","real_id","nb_assigned_ids","nb_original_fp","ratio","max_chain"))
	checkErrorWriting(err)
	//don't iterate over reals_ids since some fps don't have end date and are not present
	for real_id,set_assigned_ids := range real_id_to_assigned_ids {
		max_chain := findLongestChain(real_id,real_id_to_assigned_ids,assigned_id_to_fingerprints)
		ratio_stats := float64(real_user_id_to_nb_fps[real_id]) / float64(set_assigned_ids.Length())
		_,err = f.WriteString(fmt.Sprintf("%s,%d,%d,%f,%d\n",real_id,set_assigned_ids.Length(),
			real_user_id_to_nb_fps[real_id],ratio_stats,max_chain))
		checkErrorWriting(err)
	}

	//Create and write in the second result file
	f,err = os.Create(filename2)
	checkError(err)
	defer f.Close()
	_,err = f.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s\n","assigned_id","nb_assigned_ids","nb_fingerprints","ownership","id_ownership"))
	checkErrorWriting(err)
	for assigned_id,set_real_ids := range assigned_id_to_real_ids {
		ownership, ownership_id := computeOwnership(assigned_id_to_fingerprints[assigned_id])
		_,err = f.WriteString(fmt.Sprintf("%s,%d,%d,%f,%s\n",assigned_id,set_real_ids.Length(),
			len(assigned_id_to_fingerprints[assigned_id]),ownership,ownership_id))
		checkErrorWriting(err)
	}
}


//Types for the results in JSON
type Results1 struct {
	RealId string
	NbAssignedIds int
	NbOriginalFp int
	Ratio float64
	MaxChain int
}

type Results2 struct {
	AssignedId string
	NbAssignedIds int
	NbFingerprints int
	Ownership float64
	IdOwnership string
}

type ResultsForVisitFrequency struct {
	VisitFrequency int
	Res1 []Results1
	Res2 []Results2
}


func AnalyseScenarioResultInJSON(visitFrequency int, scenario_result []counter_and_assigned_id, fingerprint_dataset []Fingerprint) ResultsForVisitFrequency {
	/*
	   Performs an analysis of a scenario result
	*/

	counter_to_fingerprint := make(map[int]Fingerprint)
	real_user_id_to_nb_fps := make(map[string]int)

	real_id_to_assigned_ids := make(map[string]*StringSet)
	assigned_id_to_real_ids := make(map[string]*StringSet)
	assigned_id_to_fingerprints := make(map[string][]Fingerprint)

	analyseScenarioResult(scenario_result, fingerprint_dataset, counter_to_fingerprint,
		real_user_id_to_nb_fps, real_id_to_assigned_ids, assigned_id_to_real_ids, assigned_id_to_fingerprints)

	var results ResultsForVisitFrequency
	results.VisitFrequency = visitFrequency

	//don't iterate over reals_ids since some fps don't have end date and are not present
	for real_id,set_assigned_ids := range real_id_to_assigned_ids {
		max_chain := findLongestChain(real_id,real_id_to_assigned_ids,assigned_id_to_fingerprints)
		ratio_stats := float64(real_user_id_to_nb_fps[real_id]) / float64(set_assigned_ids.Length())

		results.Res1 = append(results.Res1, Results1{RealId : real_id,NbAssignedIds : set_assigned_ids.Length(),
			NbOriginalFp : real_user_id_to_nb_fps[real_id], Ratio : ratio_stats,MaxChain : max_chain})
	}


	for assigned_id,set_real_ids := range assigned_id_to_real_ids {
		ownership, ownership_id := computeOwnership(assigned_id_to_fingerprints[assigned_id])

		results.Res2 = append(results.Res2, Results2{AssignedId : assigned_id,NbAssignedIds : set_real_ids.Length(),
			NbFingerprints : len(assigned_id_to_fingerprints[assigned_id]),Ownership : ownership,IdOwnership : ownership_id})
	}

	return results
}

func findLongestChain(real_user_id string, real_id_to_assigned_ids map[string]*StringSet, assigned_id_to_fingerprints map[string][]Fingerprint) int {
	/*
		For a given user id, tries to find its longest chain
	*/

	assigned_id_to_count := make(map[string]int)

	strSet := real_id_to_assigned_ids[real_user_id].GetSet()

	for assigned_id,_ := range strSet {
		tmp_count := 0
		for _,fingerprint := range assigned_id_to_fingerprints[assigned_id] {
			if fingerprint.UserID == real_user_id {
				tmp_count += 1
			}
		}
		assigned_id_to_count[assigned_id] = tmp_count
	}

	max := 0
	for _,count := range assigned_id_to_count {
		if max < count {
			max = count
		}
	}

	return max
}

func computeOwnership(fingerprints []Fingerprint) (float64,string) {

	real_user_id_to_count := make(map[string]int)
	for _,fingerprint := range fingerprints {
		if _,is_present := real_user_id_to_count[fingerprint.UserID]; is_present {
			real_user_id_to_count[fingerprint.UserID] += 1
		} else {
			real_user_id_to_count[fingerprint.UserID] = 1
		}
	}

	max := 1
	max_key := ""

	for key,count := range real_user_id_to_count {
		if max <= count {
			max = count
			max_key = key
		}
	} 

	return (float64(max)/float64(len(fingerprints))),max_key
}