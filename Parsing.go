package main

import (
	"MimojaFirmwareToolkit/pkg/Common"
	"context"
	"github.com/hillu/go-yara"
	"io/ioutil"
)

var yaraRules *yara.Rules

func analyse(entry MFTCommon.FlashImage) error {
	reader, err := Bundle.Storage.GetFile(entry.ID.GetID())
	if err != nil {
		Bundle.Log.WithField("entry", entry).WithError(err).Errorf("could not fetch file: %v\n", err)
		return err
	}
	defer reader.Close()

	firmwareBytes, err := ioutil.ReadAll(reader)
	if err != nil {
		Bundle.Log.WithField("entry", entry).WithError(err).Errorf("could not read firmware file: %v", err)
		return err
	}

	agesa, err := MFTCommon.AnalyseAGESA(Bundle.Log.WithField("entry", entry), firmwareBytes)
	if err != nil {
		Bundle.Log.WithField("entry", entry).WithError(err).Errorf("could not read agesa: %v", err)
	}

	firmware, err := MFTCommon.AnalyseAMDFW(Bundle.Log.WithField("entry", entry), firmwareBytes)
	if err != nil {
		Bundle.Log.WithField("entry", entry).WithError(err).Errorf("could not read amd firmware: %v", err)
	}

	if agesa != nil {
		entry.AMD = &MFTCommon.AMDFirmware{
			AGESA: agesa,
		}
	}
	if firmware != nil {
		if entry.AMD == nil {
			entry.AMD = &MFTCommon.AMDFirmware{}
		}

		entry.AMD.Firmware = MFTCommon.ConvertAMDFWToMFT(firmware)

		Bundle.Log.WithField("entry", entry).Info("Storing into DB")

		for _, rom := range firmware.Roms {
			for _, directory := range rom.Directories {
				for _, entry := range directory.Entries {
					mftEntry := MFTCommon.ConvertAMDEntryToMFT(entry)
					id := mftEntry.ID.GetID()
					entryType := "amdentry"

					found, err, _ := Bundle.DB.Exists("amdentries", id)
					if !found || err != nil {
						Bundle.Storage.StoreBytes(entry.Raw, id)
					}
					Bundle.DB.StoreElement("amdentries", &entryType, mftEntry, &id)

				}
			}
		}

		_, err = Bundle.DB.ES.Update().
			Index("flashimages").
			Type("flashimage").
			Id(entry.ID.GetID()).
			Doc(map[string]interface{}{"AMD": entry.AMD}).
			Do(context.Background())

		if err != nil {
			Bundle.Log.WithField("entry", entry).WithError(err).Errorf("Could not store to elastic %v", err)
			return err
		}
	}
	return nil
}
