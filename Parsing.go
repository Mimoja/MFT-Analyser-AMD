package main

import (
	"context"
	"fmt"
	"github.com/Mimoja/MFT-Common"
	"github.com/hillu/go-yara"
	"github.com/mimoja/amdfw"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"reflect"
)


var yaraAMDRules *yara.Rules

func SetupYaraForAMD(Log *logrus.Logger) {
	c, err := yara.NewCompiler()
	if err != nil {
		Log.Fatal("Could not create yara compiler")
	}

	file, err := os.Open("amdRules.yara")
	if err != nil {
		Log.Fatalf("Could not load rules: %v", err)
	}

	c.AddFile(file, "test")

	r, err := c.GetRules()
	if err != nil {
		Log.Fatalf("Failed to compile rules: %s", err)
	}
	yaraAMDRules = r
}

func AnalyseAGESA(Log *logrus.Entry, firmwareBytes []byte) (agesas []MFTCommon.AMDAGESA, err error) {

	Log.Debug("Scanning for AGESA")
	matches, err := yaraAMDRules.ScanMem(firmwareBytes, 0, 0)
	if err != nil {
		Log.Errorf("could not scan with yara %v", err)
		return nil, err
	}

	if len(matches) != 0 {
		for _, match := range matches {
			for _, str := range match.Strings {
				switch match.Rule {
				case "AGESA":
					agesa := MFTCommon.AMDAGESA{
						Header: string(str.Data),
						Raw:    fmt.Sprintf("%q\n", firmwareBytes[str.Offset:str.Offset+100]),
						Offset: uint32(str.Offset),
					}
					agesas = append(agesas, agesa)
					Log.Debug("Matched : ", agesa.Header)
				case "Certificates":
					//TODO Parse Cert -> amdfw
				}
			}
		}

	}

	return agesas, nil
}

func AnalyseAMDFW(Log *logrus.Entry, firmwareBytes []byte) (*amdfw.Image, error) {

	Log.Infof("Searching for AGESA Magic Bytes")

	image := amdfw.Image{}

	fetOffset, err := amdfw.FindFirmwareEntryTable(firmwareBytes)
	if err != nil {
		Log.WithError(err).Info("Could not find AMD Table")
		return nil, err
	}

	Log.Infof("Found PSP Magic 0x55AA55AA at 0x%08X", fetOffset)

	fet, err := amdfw.ParseFirmwareEntryTable(firmwareBytes, fetOffset)
	if err != nil {
		Log.WithError(err).Error("Could not read AMDFirmwareEntryTable: ", err)
		return nil, err
	}

	image.FET = fet
	mapping, err := amdfw.GetFlashMapping(firmwareBytes, fet)
	if err != nil {
		Log.WithError(err).Error("Could not determin FlashMapping: ", err)
		return &image, err
	}
	image.FlashMapping = &mapping

	roms, errs := amdfw.ParseRoms(firmwareBytes, fet, mapping)
	if len(errs) != 0 {
		err = fmt.Errorf("Errors parsing images %v", errs)
	} else {
		err = nil
	}

	image.Roms = roms
	return &image, err
}

func ConvertAMDEntryToMFT(origin amdfw.Entry) MFTCommon.DBEntry {

	dbEntry := MFTCommon.DBEntry{
		ID: MFTCommon.GenerateID(origin.Raw),
		AMDBinaryEntry: MFTCommon.AMDBinaryEntry{
			Signature: fmt.Sprintf("0x%X", origin.DirectoryEntry.Reserved),
			Comment:   origin.Comment,
			TypeInfo:  origin.TypeInfo,
			Version:   origin.Version,
			Type:      fmt.Sprintf("0x%X", origin.DirectoryEntry.Type),
			Size:      fmt.Sprintf("0x%X", origin.DirectoryEntry.Size),
		},
	}

	if origin.Header != nil {

		dbEntry.Header = map[string]string{}
		reflectVal := reflect.Indirect(reflect.ValueOf(origin.Header))
		for i := 0; i < reflectVal.Type().NumField(); i++ {
			fieldName := reflectVal.Type().Field(i).Name
			fieldValue := reflectVal.Field(i)
			dbEntry.Header[fieldName] = fmt.Sprintf("0x%X", fieldValue)
		}

	}
	return dbEntry
}

func ConvertAMDFWToMFT(origin *amdfw.Image) *MFTCommon.AMDImage {
	image := MFTCommon.AMDImage{}

	if origin == nil {
		return nil
	}

	if origin.FlashMapping != nil {
		image.FlashMapping = fmt.Sprintf("0x%08X", *origin.FlashMapping)
	}

	if origin.FET != nil {
		image.FET = &MFTCommon.AMDFirmwareEntryTable{
			Signature: fmt.Sprintf("0x%08X", origin.FET.Signature),
			Location:  fmt.Sprintf("0x%08X", origin.FET.Location),
		}

		if origin.FET.ImcRomBase != nil {
			image.FET.ImcRomBase = fmt.Sprintf("0x%08X", *origin.FET.ImcRomBase)
		}
		if origin.FET.GecRomBase != nil {
			image.FET.GecRomBase = fmt.Sprintf("0x%08X", *origin.FET.GecRomBase)

		}
		if origin.FET.XHCRomBase != nil {
			image.FET.XHCRomBase = fmt.Sprintf("0x%08X", *origin.FET.XHCRomBase)
		}
		if origin.FET.PSPDirBase != nil {
			image.FET.PSPDirBase = fmt.Sprintf("0x%08X", *origin.FET.PSPDirBase)
		}
		if origin.FET.NewPSPDirBase != nil {
			image.FET.NewPSPDirBase = fmt.Sprintf("0x%08X", *origin.FET.NewPSPDirBase)
		}
		if origin.FET.BHDDirBase != nil {
			image.FET.BHDDirBase = fmt.Sprintf("0x%08X", *origin.FET.BHDDirBase)
		}
		if origin.FET.NewBHDDirBase != nil {
			image.FET.NewBHDDirBase = fmt.Sprintf("0x%08X", *origin.FET.NewBHDDirBase)
		}
	}

	for _, rom := range origin.Roms {
		newRom := MFTCommon.AMDRom{
			Type: rom.Type,
		}
		for _, directory := range rom.Directories {
			newDirectory := MFTCommon.AMDDirectory{
				Header: MFTCommon.AMDDirectoryHeader{
					Cookie:       string(directory.Header.Cookie[:]),
					Checksum:     fmt.Sprintf("0x%08X", directory.Header.Checksum),
					TotalEntries: fmt.Sprintf("0x%X", directory.Header.TotalEntries),
					Reserved:     fmt.Sprintf("0x%08X", directory.Header.Reserved),
				},
				Entries:  nil,
				Location: fmt.Sprintf("0x%08X", directory.Location),
			}
			newDirectory.Header.ChecksumValid, _ = directory.ValidateChecksum()

			for _, entry := range directory.Entries {
				newEntry := MFTCommon.AMDEntry{
					DirectoryEntry: MFTCommon.AMDDirectoryEntry{
						Type:     fmt.Sprintf("0x%X", entry.DirectoryEntry.Type),
						Size:     fmt.Sprintf("0x%X", entry.DirectoryEntry.Size),
						Location: fmt.Sprintf("0x%X", entry.DirectoryEntry.Location),
						Reserved: fmt.Sprintf("0x%X", entry.DirectoryEntry.Reserved),
					},
					DBEntry: ConvertAMDEntryToMFT(entry),
				}
				if entry.DirectoryEntry.Unknown != nil {
					newEntry.DirectoryEntry.Unknown = fmt.Sprintf("0x%X", *entry.DirectoryEntry.Unknown)
				}
				if entry.Signature != nil && len(entry.Signature) != 0 {
					newEntry.Signature = fmt.Sprintf("0x%X", entry.Signature)
				}
				if entry.Header != nil {
					newEntry.Header = map[string]string{}
					reflectVal := reflect.Indirect(reflect.ValueOf(entry.Header))
					for i := 0; i < reflectVal.Type().NumField(); i++ {
						fieldName := reflectVal.Type().Field(i).Name
						fieldValue := reflectVal.Field(i)
						newEntry.Header[fieldName] = fmt.Sprintf("0x%X", fieldValue)
					}
				}
				newDirectory.Entries = append(newDirectory.Entries, newEntry)

			}
			newRom.Directories = append(newRom.Directories, newDirectory)
		}
		image.Roms = append(image.Roms, newRom)
	}
	return &image
}

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

	agesa, err := AnalyseAGESA(Bundle.Log.WithField("entry", entry), firmwareBytes)
	if err != nil {
		Bundle.Log.WithField("entry", entry).WithError(err).Errorf("could not read agesa: %v", err)
	}

	firmware, err := AnalyseAMDFW(Bundle.Log.WithField("entry", entry), firmwareBytes)
	if err != nil {
		Bundle.Log.WithField("entry", entry).WithError(err).Errorf("could not read amd firmware: %v", err)
	}

	amdfw := &MFTCommon.AMDFirmware{}

	if agesa != nil {
		entry.AMD = amdfw
		amdfw.AGESA = agesa
	}

	if firmware != nil {
		if entry.AMD == nil {
			entry.AMD = amdfw
		}

		amdfw.Firmware = ConvertAMDFWToMFT(firmware)

		Bundle.Log.WithField("entry", entry).Info("Storing into DB")

		for _, rom := range firmware.Roms {
			for _, directory := range rom.Directories {
				for _, entry := range directory.Entries {
					mftEntry := ConvertAMDEntryToMFT(entry)
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
