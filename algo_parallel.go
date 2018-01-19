package fpTracking

import (
	"fmt"
	"os"
	"time"
	"strings"
	"gopkg.in/oleiade/reflections.v1"
	"github.com/xrash/smetrics"
)


//Definition of constants for the RuleBased results
const EXACT_FOUND = 0
const CANDIDATE_FOUND = 1
const CONFLICT = 2
const NOT_FOUND = 3


func RuleBasedLinkingParallel(fingerprint_unknown Fingerprint, user_id_to_fps map[string][]fingerprintLocalId, counter_to_fingerprint map[int]Fingerprint) (int,string){

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

	conflictPresent := false

	if len(exact_matching) > 0 {
		if candidates_have_same_id(exact_matching) {
			return EXACT_FOUND, exact_matching[0].user_id
		} else {
			//There is a conflict
			conflictPresent = true
		}
	} else if len(candidates) > 0 {
		if candidates_have_same_id(candidates) {
			return CANDIDATE_FOUND, candidates[0].user_id
		} else {
			//There is a conflict
			conflictPresent = true
		}
	}

	if conflictPresent {
		return CONFLICT, generate_new_id()
	}

	return NOT_FOUND, generate_new_id()
}


//Definition of constants for the tasks in the messages
const LINK = "link"
const ASSIGNED_ID_ACCEPTED = "acc"
const ASSIGNED_ID_NOT_ACCEPTED = "not_acc"
const DELETE_ELEMENTS_TOO_OLD = "deto"
const CLOSE_GOROUTINE = "cg"

type message struct {
	task string
	elt sequenceElt
	fp Fingerprint
	result int
	assigned_id string
	goroutine_id int
}

type osBrowserCombination struct {
	os string
	browser string
}

//Function executed by goroutines
func parallelLinking (id int, linkFingerprint func(Fingerprint, map[string][]fingerprintLocalId, map[int]Fingerprint) (int,string), ch chan message) {

	nb_max_cmp := 2
	counter_to_time := make(map[fingerprintLocalId]time.Time)
	counter_to_fingerprint := make(map[int]Fingerprint)

	os_browser_to_fps := make(map[osBrowserCombination]map[string][]fingerprintLocalId)

	var os_browser_combination osBrowserCombination
	var fp_local_id fingerprintLocalId
	result := -1
	assigned_id := ""
	var current_time time.Time
	time_limit := float64(30*24*60*60)

	for {
		rq := <- ch
		if strings.Compare(rq.task,LINK) == 0 {
			
			fp_local_id = rq.elt.fp_local_id
			current_time = rq.elt.lastVisit
			counter_to_time[fp_local_id] = current_time
			counter_to_fingerprint[fp_local_id.counter] = rq.fp
			
			//We only compare to fingerprints which as the same os and same browser as the  unknown fingerprint
			os_browser_combination = osBrowserCombination{os : rq.fp.OS, browser : rq.fp.Browser}

			result, assigned_id = linkFingerprint(rq.fp, os_browser_to_fps[os_browser_combination], counter_to_fingerprint)

			//We send the answer to the master goroutine
			ch <- message {
				result : result,
				assigned_id : assigned_id,
				goroutine_id : id,
			}
		} else if strings.Compare(rq.task,ASSIGNED_ID_ACCEPTED) == 0 {

			//We store the fingerprint to keep it for next iterations

			if len(os_browser_to_fps[os_browser_combination][assigned_id]) == nb_max_cmp {
    			//pop the first element
    			os_browser_to_fps[os_browser_combination][assigned_id] = os_browser_to_fps[os_browser_combination][assigned_id][1:]
    		}

    		if os_browser_to_fps[os_browser_combination] == nil {
    			os_browser_to_fps[os_browser_combination] = make(map[string][]fingerprintLocalId)
    		}
    		os_browser_to_fps[os_browser_combination][assigned_id] = append(os_browser_to_fps[os_browser_combination][assigned_id],fp_local_id)

		} else if strings.Compare(rq.task,ASSIGNED_ID_NOT_ACCEPTED) == 0 {
			//We do nothing

		} else if strings.Compare(rq.task,DELETE_ELEMENTS_TOO_OLD) == 0 {

			for _, user_id_to_fps := range os_browser_to_fps {
				ids_to_remove := NewStringSet()
				for user_id,fp_local_id_list := range user_id_to_fps {
					index_last_element := len(fp_local_id_list)-1
					if (index_last_element >= 0) {
						fp_local_id_tmp := fp_local_id_list[index_last_element]
						time_tmp := counter_to_time[fp_local_id_tmp]
						if current_time.Sub(time_tmp).Seconds() > time_limit {
							ids_to_remove.Add(user_id)
						}
					}
				}
				for user_id,_ := range ids_to_remove.GetSet() {
					delete(user_id_to_fps,user_id)
				}
			}

		} else if strings.Compare(rq.task,CLOSE_GOROUTINE) == 0 {

			return

		} else {
			//This case should never happen
			fmt.Println("Wrong task for goroutine",id,": task",rq.task)
			os.Exit(1)
		}
	}
}


func ReplayScenarioParallel (fingerprintDataset []Fingerprint, visitFrequency int, linkFingerprint func(Fingerprint, map[string][]fingerprintLocalId, map[int]Fingerprint) (int,string), goroutines_number int) []counter_and_assigned_id {

	/*
		Takes as input the fingerprint dataset,
        the frequency of visit in days,
        link_fingerprint, the function used for the linking strategy
	*/


	//we store all the channels into a slice of channels
	var channels []chan message

	for i := 0; i < goroutines_number; i++ {
		ch := make(chan message)
		defer close(ch)
		channels = append(channels,ch)
		go parallelLinking(i, linkFingerprint, ch)
	}

	//we keep the number of fingerprints remembered by each goroutine
	var number_of_fingerprints_per_goroutine []int
	for i := 0; i < goroutines_number; i++ {
		number_of_fingerprints_per_goroutine = append(number_of_fingerprints_per_goroutine,0)
	}

	replaySequence := generateReplaySequence(fingerprintDataset,visitFrequency)
	counter_to_fingerprint := make(map[int]Fingerprint)
	for _,fingerprint := range fingerprintDataset {
		counter_to_fingerprint[fingerprint.Counter] = fingerprint
	}

	var fps_available []counter_and_assigned_id //Set of know fingerprints (new_counter,assigned_id)

	fmt.Println("length : ",len(replaySequence))
	for index, elt := range replaySequence {
		if index % 500 == 0 {
			fmt.Println("index : ",index)
		}
		counter := elt.fp_local_id.counter
		fingerprint_unknown := counter_to_fingerprint[counter]


		//We send to all goroutines the instruction to try to link the fingerprint
		for i := 0; i < goroutines_number; i++ {
			channels[i] <- message{task : LINK,elt : elt, fp : fingerprint_unknown}
		}

		//We wait for the answers and we save them
		answers := make([]message,goroutines_number)
		for i := 0; i < goroutines_number; i++ {
			answers[i] = <- channels[i]
		}

		//we look at the conflicts to take a decision
		conflictPresent := false
		candidate_found_count := 0
		chosen_goroutine_id := -1
		exactFoundPresent := false
		for i := 0; i < goroutines_number; i++ {
			if answers[i].result == EXACT_FOUND {
				chosen_goroutine_id = answers[i].goroutine_id
				exactFoundPresent = true
			} else if answers[i].result == CANDIDATE_FOUND {
				candidate_found_count += 1
				if !exactFoundPresent {
					chosen_goroutine_id = answers[i].goroutine_id
				}
			} else if answers[i].result == CONFLICT {
				conflictPresent = true
			} 
		}

		//Now, we take a decision
		if !exactFoundPresent && (conflictPresent || candidate_found_count > 1 || candidate_found_count < 1) {
			chosen_goroutine_id = min_index_in_int_slice(number_of_fingerprints_per_goroutine)
		}

		number_of_fingerprints_per_goroutine[chosen_goroutine_id] += 1

		assigned_id := assigned_id_from_goroutine(answers, chosen_goroutine_id)

		//We send the decision to the goroutines
		for i := 0; i < goroutines_number; i++ {
			if i == chosen_goroutine_id {
				channels[i] <- message{task : ASSIGNED_ID_ACCEPTED}
			} else {
				channels[i] <- message{task : ASSIGNED_ID_NOT_ACCEPTED}
			}
		}

        
        fps_available = append(fps_available, counter_and_assigned_id{fp_local_id: elt.fp_local_id, assigned_id: assigned_id})
        

        //every 2000 elements we delete elements too old
        if index % 2000 == 0 {
        	for i := 0; i < goroutines_number; i++ {
        		channels[i] <- message{task : DELETE_ELEMENTS_TOO_OLD}
        	}
        }
        
	}

	for i := 0; i < goroutines_number; i++ {
		channels[i] <- message{task : CLOSE_GOROUTINE}
	}

	return fps_available
}

func min_index_in_int_slice (slice []int) int {
	length := len(slice)
	min := slice[0]
	min_index := 0

	for i := 1; i < length; i++ {
		if slice[i] < min {
			min = slice[i]
			min_index = i
		}
	}

	return min_index
}

func assigned_id_from_goroutine (answers []message, id int) string {
	for _, answer := range answers {
		if answer.goroutine_id == id {
			return answer.assigned_id
		}
	}
	//This should never happen
	fmt.Println("Error in assigned_id_from_goroutine")
	return ""
}