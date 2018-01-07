package fpTracking

import (
	"fmt"
	"os"
	"time"
	"math/rand"
	"strings"
	"sync"
	"gopkg.in/oleiade/reflections.v1"
	"github.com/xrash/smetrics"
)


//Definition of constants for the RuleBased results
const FOUND = 0
const CONFLICT = 1
const NOT_FOUND = 2


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
			return FOUND, exact_matching[0].user_id
		} else {
			//There is a conflict
			conflictPresent = true
		}
	} else if len(candidates) > 0 {
		if candidates_have_same_id(candidates) {
			return FOUND, candidates[0].user_id
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
const LINK_ANSWER = "link_answer"
const TAKE_NOTE_OF_DECISION = "tnod"
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
func parallelLinking (id int, linkFingerprint func(Fingerprint, map[string][]fingerprintLocalId, map[int]Fingerprint) (int,string), request <- chan message, answer chan <- message, w *sync.WaitGroup) {

	//user_id_to_fps := make(map[string][]fingerprintLocalId)
	//fmt.Println("TEST : initialisation goroutine",id)
	nb_max_cmp := 2
	counter_to_time := make(map[fingerprintLocalId]time.Time)
	counter_to_fingerprint := make(map[int]Fingerprint)

	os_browser_to_fps := make(map[osBrowserCombination]map[string][]fingerprintLocalId)

	var os_browser_combination osBrowserCombination
	var fp_local_id fingerprintLocalId
	result := -1
	assigned_id := ""

	for {
		rq := <- request
		if strings.Compare(rq.task,LINK) == 0 {
			
			fp_local_id = rq.elt.fp_local_id
			counter_to_time[fp_local_id] = rq.elt.lastVisit
			counter_to_fingerprint[fp_local_id.counter] = rq.fp
			
			//We only compare to fingerprints which as the same os and same browser as the  unknown fingerprint
			os_browser_combination = osBrowserCombination{os : rq.fp.OS, browser : rq.fp.Browser}
			//fmt.Println("goroutine",id,": combination :",os_browser_combination)

			result, assigned_id = linkFingerprint(rq.fp, os_browser_to_fps[os_browser_combination], counter_to_fingerprint)

			/*TEST_message := message {
				task : LINK_ANSWER,
				result : result,
				assigned_id : assigned_id,
				goroutine_id : id,
			}
			fmt.Println("TEST : message de goroutine",id,": task : ",TEST_message.task," result :",
				TEST_message.result," assigned_id :",TEST_message.assigned_id, " goroutine_id :",TEST_message.goroutine_id)*/

			//We send the answer to the master goroutine
			answer <- message {
				task : LINK_ANSWER,
				result : result,
				assigned_id : assigned_id,
				goroutine_id : id,
			}
		} else if strings.Compare(rq.task,TAKE_NOTE_OF_DECISION) == 0 {

			//We look if the current goroutine is the one selected by the master
			//if true, we store the fingerprint to keep it for next iterations
			//else, we do nothing
			if rq.goroutine_id == id {
				//fmt.Println("goroutine",id,"takes note of decision")
				//fmt.Println("same combination ? ",os_browser_combination)
				if len(os_browser_to_fps[os_browser_combination][assigned_id]) == nb_max_cmp {
        			//pop the first element
        			os_browser_to_fps[os_browser_combination][assigned_id] = os_browser_to_fps[os_browser_combination][assigned_id][1:]
        		}

        		if os_browser_to_fps[os_browser_combination] == nil {
        			os_browser_to_fps[os_browser_combination] = make(map[string][]fingerprintLocalId)
        		}
        		os_browser_to_fps[os_browser_combination][assigned_id] = append(os_browser_to_fps[os_browser_combination][assigned_id],fp_local_id)
			} /*else {fmt.Println("goroutine",id,"does NOT take note of decision")}*/

			//goroutine wait for the other to finish
			w.Done()
			//fmt.Println("goroutine",id," has finished and is waiting for others ...")
			w.Wait()
			//fmt.Println("goroutine",id," is unlocked !")

		} else if strings.Compare(rq.task,CLOSE_GOROUTINE) == 0 {

			//fmt.Println("goroutine",id,"is closing ...")
			return

		} else {
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
        filename, path to the file to save results of the scenario
	*/

	request := make(chan message)
	defer close(request)
	answer := make(chan message)
	defer close(answer)

	var w sync.WaitGroup

	//fmt.Println("TEST : nombre de goroutines :",goroutines_number)

	for i := 0; i < goroutines_number; i++ {
		go parallelLinking(i, linkFingerprint, request, answer, &w)
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
		//fmt.Println("===== INDEX : ",index,"=====")
		counter := elt.fp_local_id.counter
		fingerprint_unknown := counter_to_fingerprint[counter]


		//We send to all goroutines the instruction to try to link the fingerprint
		for i := 0; i < goroutines_number; i++ {
			request <- message{task : LINK,elt : elt, fp : fingerprint_unknown}
		}
		//fmt.Println("All the request were read by goroutines")

		//We wait for the answers and we save them
		//we also look for conflicts, the number of "FOUND" answers ...
		var answers []message
		conflictPresent := false
		found_count := 0
		chosen_goroutine_id := -1
		for i := 0; i < goroutines_number; i++ {
			//This list will be ordered by the order of answer messages
			msg := <-answer
			answers = append(answers,msg)

			if msg.result == CONFLICT {
				conflictPresent = true
			} else if msg.result == FOUND {
				found_count += 1
				chosen_goroutine_id = msg.goroutine_id
			}
		}
		//fmt.Println("All answers from goroutines were read by master")
		//fmt.Println("conflictPresent :",conflictPresent,"found_count :",found_count, "chosen_goroutine_id",chosen_goroutine_id)

		//Now, we take a decision
		if conflictPresent || found_count > 1 || found_count < 1 {
			chosen_goroutine_id = random_between_range(0,goroutines_number - 1)
		}
		//fmt.Println("After decision, chosen_goroutine_id :",chosen_goroutine_id)

		assigned_id := assigned_id_from_goroutine(answers, chosen_goroutine_id)
		//fmt.Println("So, assigned_id :",assigned_id)

		//We send the decision to all the goroutines
		w.Add(goroutines_number)
		for i := 0; i < goroutines_number; i++ {
			request <- message{task : TAKE_NOTE_OF_DECISION, goroutine_id : chosen_goroutine_id}
		}

        
        fps_available = append(fps_available, counter_and_assigned_id{fp_local_id: elt.fp_local_id, assigned_id: assigned_id})

        //fmt.Println("We Wait for the goroutines to finish")
        w.Wait()
        //fmt.Println("Master unlocked !")
        

        /*every 2000 elements we delete elements too old
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
        }*/
	}

	//fmt.Println("End of ReplayScenarioParallel function")
	//fmt.Println("Closing goroutines ...")
	for i := 0; i < goroutines_number; i++ {
		request <- message{task : CLOSE_GOROUTINE}
	}
	//fmt.Println("All the goroutines are closed")
	//os.Exit(0)
	return fps_available
}

func random_between_range (min, max int) int {
	rand.Seed(time.Now().UTC().UnixNano())
	return rand.Intn(max + 1 - min) + min
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