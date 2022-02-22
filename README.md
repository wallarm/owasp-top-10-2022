# OWASP Top-10 2022 proposal

Statistical approach to build OWASP Top Ten list. 
This repository includes code, data and calculation methodology. 

Our proposal is not an official list, but the research work and open methodology that allow everyone to repeat calculations and get similar results. 

## Repository

* owasp.py - a script that download data from Vulners API and calculate statistics
* owasp.json.part. - two parts of data export (GitHub 25MB limit bypass) 

## How to run

```
cat owasp.json.part* > owasp.json
python owasp.py
```

## Related work

OWASP Top-10 2021. Statistics-based proposal:
https://lab.wallarm.com/owasp-top-10-2021-proposal-based-on-a-statistical-data/
