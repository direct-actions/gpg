action.yaml: tmp
	mv tmp action.yaml

tmp:
	sed -n '1,/---BEGIN JQ SCRIPT---/p' action.yaml > tmp
	sed 's/^/              /' keys_to_json.jq >> tmp
	sed -n '/---END JQ SCRIPT---/,$$p' action.yaml >> tmp 

