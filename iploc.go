package iptrace

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
)

func ip_trace(ip string) (latitude, longitude float64, city, country string, err error) {
	resp, err := http.Get("https://api.apibundle.io/ip-lookup?apikey=7cf5190171984a06aa074cb287d9d6c4&ip=" + string(ip))
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	var (
		result map[string]interface{}
	)

	if err := json.Unmarshal(body, &result); err != nil {
		log.Fatalln(err)
	}

	if raw, ok := result["latitude"]; ok {
		latitude = raw.(float64)
	} else {
		log.Println("No latitude found")
	}
	if raw, ok := result["longitude"]; ok {
		longitude = raw.(float64)
	} else {
		log.Println("No longitude found")
	}

	rawCity, ok := result["city"].(map[string]interface{})
	if !ok {
		log.Fatalln("city key missing or not an object")
	}
	cityName, ok := rawCity["name"].(string)
	if !ok {
		log.Fatalln("city.name missing or not a string")
	}
	city = cityName

	rawCountry, ok := result["country"].(map[string]interface{})
	if !ok {
		log.Fatalln("city key missing or not an object")
	}
	countryName, ok := rawCountry["name"].(string)
	if !ok {
		log.Fatalln("city.name missing or not a string")
	}
	country = countryName

	return

}
