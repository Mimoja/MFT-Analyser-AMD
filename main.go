package main

import (
	"github.com/Mimoja/MFT-Common"
	"encoding/json"
)

var Bundle MFTCommon.AppBundle

func main() {
	Bundle = MFTCommon.Init("AMDEntryTableAnalyser")
	SetupYaraForAMD(Bundle.Log)

	Bundle.MessageQueue.BiosImagesQueue.RegisterCallback("AMDAnalyser", func(payload string) error {

		Bundle.Log.WithField("payload", payload).Info("Got new Message!")
		var file MFTCommon.FlashImage
		err := json.Unmarshal([]byte(payload), &file)
		if err != nil {
			Bundle.Log.WithField("payload", payload).Error("Could not unmarshall json: %v\n", err)
		}

		err = analyse(file)

		return err
	})
	Bundle.Log.Info("Starting up!")
	select {}
}
