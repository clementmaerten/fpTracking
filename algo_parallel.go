package fpTracking

import (
	"fmt"
	"time"
	"strings"
)

type message struct {
	task string
	elt sequenceElt
	fp Fingerprint
}

type osBrowserCombination struct {
	os string
	browser string
}

func parallelLinking (id int, linkFingerprint func(Fingerprint, map[string][]fingerprintLocalId, map[int]Fingerprint) string, request <- chan message, answer chan <- message) {

	//user_id_to_fps := make(map[string][]fingerprintLocalId)
	counter_to_time := make(map[fingerprintLocalId]time.Time)
	counter_to_fingerprint := make(map[int]Fingerprint)

	os_browser_to_fps := make(map[osBrowserCombination]map[string][]fingerprintLocalId)


	for {
		rq := <- request
		if strings.Compare(rq.task,"link") == 0 {
			
			counter_to_time[rq.elt.fp_local_id] = rq.elt.lastVisit
			counter_to_fingerprint[rq.elt.fp_local_id.counter] = rq.fp
			
			//We only compare to fingerprints which as the same os and same browser as the  unknown fingerprint
			os_browser_combination := osBrowserCombination{os : rq.fp.OS, browser : rq.fp.Browser}


			assigned_id := linkFingerprint(rq.fp, os_browser_to_fps[os_browser_combination], counter_to_fingerprint)



		} else {
			fmt.Println("Wrong task for goroutine",id)
		}
	}
}


func ReplayScenarioParallel (fingerprintDataset []Fingerprint, visitFrequency int, linkFingerprint func(Fingerprint, map[string][]fingerprintLocalId, map[int]Fingerprint) string) []counter_and_assigned_id {

	/*
		Takes as input the fingerprint dataset,
        the frequency of visit in days,
        link_fingerprint, the function used for the linking strategy
        filename, path to the file to save results of the scenario
	*/

    goroutines_number := 4

    request := make(chan message)
    defer close(request)
    answer := make(chan message)
    defer close(answer)

    for i := 0; i < goroutines_number; i++ {
    	go parallelLinking(i, linkFingerprint, request, answer)
    }


	nb_max_cmp := 2
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

		for i := 0; i < goroutines_number; i++ {
			request <- message{task : "link",elt : elt, fp : fingerprint_unknown}
		}


		
        
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

