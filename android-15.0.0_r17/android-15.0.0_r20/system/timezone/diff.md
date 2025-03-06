```diff
diff --git a/input_data/android/telephonylookup.txt b/input_data/android/telephonylookup.txt
index 9e73e14..6802417 100644
--- a/input_data/android/telephonylookup.txt
+++ b/input_data/android/telephonylookup.txt
@@ -1,5 +1,5 @@
 #
-# Copyright 2019, The Android Open Source Project
+# Copyright 2024, The Android Open Source Project
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
@@ -65,3 +65,1241 @@ networks:<
   countryIsoCode: "as"
 >
 
+# Countries / regions by Mobile Country Code (MCC).
+#
+# The table below is built from three main resources:
+# 1) ITU "LIST OF MOBILE COUNTRY OR GEOGRAPHICAL AREA CODES (POSITION ON 1 FEBRUARY 2017)"
+#    available here: http://handle.itu.int/11.1002/pub/80f1788f-en
+# 2) The ISO 3166 country codes list, available here:
+#    https://www.iso.org/iso-3166-country-codes.html
+# 3) Android fine-tuning based on observations and reported errors
+#
+# This table may not be completely accurate.
+#
+# Entries are sorted by MCC (Asc). For MCCs that cover multiple countryIsoCodes, the first
+# ISO code is considered "default" (often the one with the largest population).
+
+mobile_countries:<
+    mcc: "202"
+    countryIsoCodes: "gr" # Greece
+>
+
+mobile_countries:<
+    mcc: "204"
+    countryIsoCodes: "nl" # Netherlands (Kingdom of the)
+>
+
+mobile_countries:<
+    mcc: "206"
+    countryIsoCodes: "be" # Belgium
+>
+
+mobile_countries:<
+    mcc: "208"
+    countryIsoCodes: "fr" # France
+>
+
+mobile_countries:<
+    mcc: "212"
+    countryIsoCodes: "mc" # Monaco (Principality of)
+>
+
+mobile_countries:<
+    mcc: "213"
+    countryIsoCodes: "ad" # Andorra (Principality of)
+>
+
+mobile_countries:<
+    mcc: "214"
+    countryIsoCodes: "es" # Spain
+>
+
+mobile_countries:<
+    mcc: "216"
+    countryIsoCodes: "hu" # Hungary (Republic of)
+>
+
+mobile_countries:<
+    mcc: "218"
+    countryIsoCodes: "ba" # Bosnia and Herzegovina
+>
+
+mobile_countries:<
+    mcc: "219"
+    countryIsoCodes: "hr" # Croatia (Republic of)
+>
+
+mobile_countries:<
+    mcc: "220"
+    countryIsoCodes: "rs" # Serbia (Republic of)
+>
+
+mobile_countries:<
+    mcc: "221"
+    countryIsoCodes: "xk" # Kosovo
+>
+
+mobile_countries:<
+    mcc: "222"
+    countryIsoCodes: "it" # Italy
+>
+
+mobile_countries:<
+    mcc: "225"
+    countryIsoCodes: "va" # Vatican City State
+>
+
+mobile_countries:<
+    mcc: "226"
+    countryIsoCodes: "ro" # Romania
+>
+
+mobile_countries:<
+    mcc: "228"
+    countryIsoCodes: "ch" # Switzerland (Confederation of)
+>
+
+mobile_countries:<
+    mcc: "230"
+    countryIsoCodes: "cz" # Czechia
+>
+
+mobile_countries:<
+    mcc: "231"
+    countryIsoCodes: "sk" # Slovak Republic
+>
+
+mobile_countries:<
+    mcc: "232"
+    countryIsoCodes: "at" # Austria
+>
+
+mobile_countries:<
+    mcc: "234"
+    countryIsoCodes: "gb" # United Kingdom of Great Britain and Northern Ireland
+
+    # Same UTC offset as "gb"
+    # countryIsoCodes: "gg" # Guernsey
+    # countryIsoCodes: "im" # Isle of Man
+    # countryIsoCodes: "je" # Jersey
+>
+
+mobile_countries:<
+    mcc: "235"
+    countryIsoCodes: "gb" # United Kingdom of Great Britain and Northern Ireland
+>
+
+mobile_countries:<
+    mcc: "238"
+    countryIsoCodes: "dk" # Denmark
+>
+
+mobile_countries:<
+    mcc: "240"
+    countryIsoCodes: "se" # Sweden
+>
+
+mobile_countries:<
+    mcc: "242"
+    countryIsoCodes: "no" # Norway
+>
+
+mobile_countries:<
+    mcc: "244"
+    countryIsoCodes: "fi" # Finland
+>
+
+mobile_countries:<
+    mcc: "246"
+    countryIsoCodes: "lt" # Lithuania (Republic of)
+>
+
+mobile_countries:<
+    mcc: "247"
+    countryIsoCodes: "lv" # Latvia (Republic of)
+>
+
+mobile_countries:<
+    mcc: "248"
+    countryIsoCodes: "ee" # Estonia (Republic of)
+>
+
+mobile_countries:<
+    mcc: "250"
+    countryIsoCodes: "ru" # Russian Federation
+>
+
+mobile_countries:<
+    mcc: "255"
+    countryIsoCodes: "ua" # Ukraine
+>
+
+mobile_countries:<
+    mcc: "257"
+    countryIsoCodes: "by" # Belarus (Republic of)
+>
+
+mobile_countries:<
+    mcc: "259"
+    countryIsoCodes: "md" # Moldova (Republic of)
+>
+
+mobile_countries:<
+    mcc: "260"
+    countryIsoCodes: "pl" # Poland (Republic of)
+>
+
+mobile_countries:<
+    mcc: "262"
+    countryIsoCodes: "de" # Germany (Federal Republic of)
+>
+
+mobile_countries:<
+    mcc: "266"
+    countryIsoCodes: "gi" # Gibraltar
+>
+
+mobile_countries:<
+    mcc: "268"
+    countryIsoCodes: "pt" # Portugal
+>
+
+mobile_countries:<
+    mcc: "270"
+    countryIsoCodes: "lu" # Luxembourg
+>
+
+mobile_countries:<
+    mcc: "272"
+    countryIsoCodes: "ie" # Ireland
+>
+
+mobile_countries:<
+    mcc: "274"
+    countryIsoCodes: "is" # Iceland
+>
+
+mobile_countries:<
+    mcc: "276"
+    countryIsoCodes: "al" # Albania (Republic of)
+>
+
+mobile_countries:<
+    mcc: "278"
+    countryIsoCodes: "mt" # Malta
+>
+
+mobile_countries:<
+    mcc: "280"
+    countryIsoCodes: "cy" # Cyprus (Republic of)
+>
+
+mobile_countries:<
+    mcc: "282"
+    countryIsoCodes: "ge" # Georgia
+>
+
+mobile_countries:<
+    mcc: "283"
+    countryIsoCodes: "am" # Armenia (Republic of)
+>
+
+mobile_countries:<
+    mcc: "284"
+    countryIsoCodes: "bg" # Bulgaria (Republic of)
+>
+
+mobile_countries:<
+    mcc: "286"
+    countryIsoCodes: "tr" # Turkey
+>
+
+mobile_countries:<
+    mcc: "288"
+    countryIsoCodes: "fo" # Faroe Islands
+>
+
+mobile_countries:<
+    mcc: "289"
+    countryIsoCodes: "ge" # Abkhazia (Georgia)
+>
+
+mobile_countries:<
+    mcc: "290"
+    countryIsoCodes: "gl" # Greenland (Denmark)
+>
+
+mobile_countries:<
+    mcc: "292"
+    countryIsoCodes: "sm" # San Marino (Republic of)
+>
+
+mobile_countries:<
+    mcc: "293"
+    countryIsoCodes: "si" # Slovenia (Republic of)
+>
+
+mobile_countries:<
+    mcc: "294"
+    countryIsoCodes: "mk" # The Former Yugoslav Republic of Macedonia
+>
+
+mobile_countries:<
+    mcc: "295"
+    countryIsoCodes: "li" # Liechtenstein (Principality of)
+>
+
+mobile_countries:<
+    mcc: "297"
+    countryIsoCodes: "me" # Montenegro
+>
+
+mobile_countries:<
+    mcc: "302"
+    countryIsoCodes: "ca" # Canada
+>
+
+mobile_countries:<
+    mcc: "308"
+    countryIsoCodes: "pm" # Saint Pierre and Miquelon
+>
+
+mobile_countries:<
+    mcc: "310"
+    countryIsoCodes: "us" # United States of America
+>
+
+mobile_countries:<
+    mcc: "311"
+    countryIsoCodes: "us" # United States of America
+>
+
+mobile_countries:<
+    mcc: "312"
+    countryIsoCodes: "us" # United States of America
+>
+
+mobile_countries:<
+    mcc: "313"
+    countryIsoCodes: "us" # United States of America
+>
+
+mobile_countries:<
+    mcc: "314"
+    countryIsoCodes: "us" # United States of America
+>
+
+mobile_countries:<
+    mcc: "315"
+    countryIsoCodes: "us" # United States of America
+>
+
+mobile_countries:<
+    mcc: "316"
+    countryIsoCodes: "us" # United States of America
+>
+
+mobile_countries:<
+    mcc: "330"
+    countryIsoCodes: "pr" # Puerto Rico
+>
+
+mobile_countries:<
+    mcc: "332"
+    countryIsoCodes: "vi" # United States Virgin Islands
+>
+
+mobile_countries:<
+    mcc: "334"
+    countryIsoCodes: "mx" # Mexico
+>
+
+mobile_countries:<
+    mcc: "338"
+    countryIsoCodes: "jm" # Jamaica
+>
+
+mobile_countries:<
+    mcc: "340"
+    countryIsoCodes: "gp" # Default: Guadeloupe
+
+    countryIsoCodes: "gf" # French Guiana
+
+    # Same UTC offset as "gp"
+    # countryIsoCodes: "bl" # Saint Barthélemy
+    # countryIsoCodes: "mf" # Collectivity of Saint Martin
+    # countryIsoCodes: "mq" # Martinique
+>
+
+mobile_countries:<
+    mcc: "342"
+    countryIsoCodes: "bb" # Barbados
+>
+
+mobile_countries:<
+    mcc: "344"
+    countryIsoCodes: "ag" # Antigua and Barbuda
+>
+
+mobile_countries:<
+    mcc: "346"
+    countryIsoCodes: "ky" # Cayman Islands
+>
+
+mobile_countries:<
+    mcc: "348"
+    countryIsoCodes: "vg" # British Virgin Islands
+>
+
+mobile_countries:<
+    mcc: "350"
+    countryIsoCodes: "bm" # Bermuda
+>
+
+mobile_countries:<
+    mcc: "352"
+    countryIsoCodes: "gd" # Grenada
+>
+
+mobile_countries:<
+    mcc: "354"
+    countryIsoCodes: "ms" # Montserrat
+>
+
+mobile_countries:<
+    mcc: "356"
+    countryIsoCodes: "kn" # Saint Kitts and Nevis
+>
+
+mobile_countries:<
+    mcc: "358"
+    countryIsoCodes: "lc" # Saint Lucia
+>
+
+mobile_countries:<
+    mcc: "360"
+    countryIsoCodes: "vc" # Saint Vincent and the Grenadines
+>
+
+mobile_countries:<
+    mcc: "362"
+    countryIsoCodes: "cw" # Default: Curaçao
+
+    # Same UTC offset as "cw"
+    # countryIsoCodes: "bq" # Caribbean Netherlands
+    # countryIsoCodes: "sx" # Sint Maarten
+>
+
+mobile_countries:<
+    mcc: "363"
+    countryIsoCodes: "aw" # Aruba
+>
+
+mobile_countries:<
+    mcc: "364"
+    countryIsoCodes: "bs" # Bahamas (Commonwealth of the)
+>
+
+mobile_countries:<
+    mcc: "365"
+    countryIsoCodes: "ai" # Anguilla
+>
+
+mobile_countries:<
+    mcc: "366"
+    countryIsoCodes: "dm" # Dominica (Commonwealth of)
+>
+
+mobile_countries:<
+    mcc: "368"
+    countryIsoCodes: "cu" # Cuba
+>
+
+mobile_countries:<
+    mcc: "370"
+    countryIsoCodes: "do" # Dominican Republic
+>
+
+mobile_countries:<
+    mcc: "372"
+    countryIsoCodes: "ht" # Haiti (Republic of)
+>
+
+mobile_countries:<
+    mcc: "374"
+    countryIsoCodes: "tt" # Trinidad and Tobago
+>
+
+mobile_countries:<
+    mcc: "376"
+    countryIsoCodes: "tc" # Turks and Caicos Islands
+>
+
+mobile_countries:<
+    mcc: "400"
+    countryIsoCodes: "az" # Azerbaijani Republic
+>
+
+mobile_countries:<
+    mcc: "401"
+    countryIsoCodes: "kz" # Kazakhstan (Republic of)
+>
+
+mobile_countries:<
+    mcc: "402"
+    countryIsoCodes: "bt" # Bhutan (Kingdom of)
+>
+
+mobile_countries:<
+    mcc: "404"
+    countryIsoCodes: "in" # India (Republic of)
+>
+
+mobile_countries:<
+    mcc: "405"
+    countryIsoCodes: "in" # India (Republic of)
+>
+
+mobile_countries:<
+    mcc: "406"
+    countryIsoCodes: "in" # India (Republic of)
+>
+
+mobile_countries:<
+    mcc: "410"
+    countryIsoCodes: "pk" # Pakistan (Islamic Republic of)
+>
+
+mobile_countries:<
+    mcc: "412"
+    countryIsoCodes: "af" # Afghanistan
+>
+
+mobile_countries:<
+    mcc: "413"
+    countryIsoCodes: "lk" # Sri Lanka (Democratic Socialist Republic of)
+>
+
+mobile_countries:<
+    mcc: "414"
+    countryIsoCodes: "mm" # Myanmar (the Republic of the Union of)
+>
+
+mobile_countries:<
+    mcc: "415"
+    countryIsoCodes: "lb" # Lebanon
+>
+
+mobile_countries:<
+    mcc: "416"
+    countryIsoCodes: "jo" # Jordan (Hashemite Kingdom of)
+>
+
+mobile_countries:<
+    mcc: "417"
+    countryIsoCodes: "sy" # Syrian Arab Republic
+>
+
+mobile_countries:<
+    mcc: "418"
+    countryIsoCodes: "iq" # Iraq (Republic of)
+>
+
+mobile_countries:<
+    mcc: "419"
+    countryIsoCodes: "kw" # Kuwait (State of)
+>
+
+mobile_countries:<
+    mcc: "420"
+    countryIsoCodes: "sa" # Saudi Arabia (Kingdom of)
+>
+
+mobile_countries:<
+    mcc: "421"
+    countryIsoCodes: "ye" # Yemen (Republic of)
+>
+
+mobile_countries:<
+    mcc: "422"
+    countryIsoCodes: "om" # Oman (Sultanate of)
+>
+
+mobile_countries:<
+    mcc: "423"
+    countryIsoCodes: "ps" # Palestine
+>
+
+mobile_countries:<
+    mcc: "424"
+    countryIsoCodes: "ae" # United Arab Emirates
+>
+
+mobile_countries:<
+    mcc: "425"
+    countryIsoCodes: "il" # Israel (State of)
+>
+
+mobile_countries:<
+    mcc: "426"
+    countryIsoCodes: "bh" # Bahrain (Kingdom of)
+>
+
+mobile_countries:<
+    mcc: "427"
+    countryIsoCodes: "qa" # Qatar (State of)
+>
+
+mobile_countries:<
+    mcc: "428"
+    countryIsoCodes: "mn" # Mongolia
+>
+
+mobile_countries:<
+    mcc: "429"
+    countryIsoCodes: "np" # Nepal (Federal Democratic Republic of)
+>
+
+mobile_countries:<
+    mcc: "430"
+    countryIsoCodes: "ae" # United Arab Emirates
+>
+
+mobile_countries:<
+    mcc: "431"
+    countryIsoCodes: "ae" # United Arab Emirates
+>
+
+mobile_countries:<
+    mcc: "432"
+    countryIsoCodes: "ir" # Iran (Islamic Republic of)
+>
+
+mobile_countries:<
+    mcc: "434"
+    countryIsoCodes: "uz" # Uzbekistan (Republic of)
+>
+
+mobile_countries:<
+    mcc: "436"
+    countryIsoCodes: "tj" # Tajikistan (Republic of)
+>
+
+mobile_countries:<
+    mcc: "437"
+    countryIsoCodes: "kg" # Kyrgyz Republic
+>
+
+mobile_countries:<
+    mcc: "438"
+    countryIsoCodes: "tm" # Turkmenistan
+>
+
+mobile_countries:<
+    mcc: "440"
+    countryIsoCodes: "jp" # Japan
+>
+
+mobile_countries:<
+    mcc: "441"
+    countryIsoCodes: "jp" # Japan
+>
+
+mobile_countries:<
+    mcc: "450"
+    countryIsoCodes: "kr" # Korea (Republic of)
+>
+
+mobile_countries:<
+    mcc: "452"
+    countryIsoCodes: "vn" # Viet Nam (Socialist Republic of)
+>
+
+mobile_countries:<
+    mcc: "454"
+    countryIsoCodes: "hk" # Hong Kong, China
+>
+
+mobile_countries:<
+    mcc: "455"
+    countryIsoCodes: "mo" # Macao, China
+>
+
+mobile_countries:<
+    mcc: "456"
+    countryIsoCodes: "kh" # Cambodia (Kingdom of)
+>
+
+mobile_countries:<
+    mcc: "457"
+    countryIsoCodes: "la" # Lao People's Democratic Republic
+>
+
+mobile_countries:<
+    mcc: "460"
+    countryIsoCodes: "cn" # China (People's Republic of)
+>
+
+mobile_countries:<
+    mcc: "461"
+    countryIsoCodes: "cn" # China (People's Republic of)
+>
+
+mobile_countries:<
+    mcc: "466"
+    countryIsoCodes: "tw" # Taiwan, China
+>
+
+mobile_countries:<
+    mcc: "467"
+    countryIsoCodes: "kp" # Democratic People's Republic of Korea
+>
+
+mobile_countries:<
+    mcc: "470"
+    countryIsoCodes: "bd" # Bangladesh (People's Republic of)
+>
+
+mobile_countries:<
+    mcc: "472"
+    countryIsoCodes: "mv" # Maldives (Republic of)
+>
+
+mobile_countries:<
+    mcc: "502"
+    countryIsoCodes: "my" # Malaysia
+>
+
+mobile_countries:<
+    mcc: "505"
+    countryIsoCodes: "au" # Default: Australia
+
+    countryIsoCodes: "nf" # Norfolk Island
+>
+
+mobile_countries:<
+    mcc: "510"
+    countryIsoCodes: "id" # Indonesia (Republic of)
+>
+
+mobile_countries:<
+    mcc: "514"
+    countryIsoCodes: "tl" # Timor-Leste (Democratic Republic of)
+>
+
+mobile_countries:<
+    mcc: "515"
+    countryIsoCodes: "ph" # Philippines (Republic of the)
+>
+
+mobile_countries:<
+    mcc: "520"
+    countryIsoCodes: "th" # Thailand
+>
+
+mobile_countries:<
+    mcc: "525"
+    countryIsoCodes: "sg" # Singapore (Republic of)
+>
+
+mobile_countries:<
+    mcc: "528"
+    countryIsoCodes: "bn" # Brunei Darussalam
+>
+
+mobile_countries:<
+    mcc: "530"
+    countryIsoCodes: "nz" # New Zealand
+>
+
+mobile_countries:<
+    mcc: "534"
+    countryIsoCodes: "mp" # Northern Mariana Islands (Commonwealth of the)
+>
+
+mobile_countries:<
+    mcc: "535"
+    countryIsoCodes: "gu" # Guam (*)
+>
+
+mobile_countries:<
+    mcc: "536"
+    countryIsoCodes: "nr" # Nauru (Republic of)
+>
+
+mobile_countries:<
+    mcc: "537"
+    countryIsoCodes: "pg" # Papua New Guinea
+>
+
+mobile_countries:<
+    mcc: "539"
+    countryIsoCodes: "to" # Tonga (Kingdom of)
+>
+
+mobile_countries:<
+    mcc: "540"
+    countryIsoCodes: "sb" # Solomon Islands
+>
+
+mobile_countries:<
+    mcc: "541"
+    countryIsoCodes: "vu" # Vanuatu (Republic of)
+>
+
+mobile_countries:<
+    mcc: "542"
+    countryIsoCodes: "fj" # Fiji (Republic of)
+>
+
+mobile_countries:<
+    mcc: "543"
+    countryIsoCodes: "wf" # Wallis and Futuna
+>
+
+mobile_countries:<
+    mcc: "544"
+    countryIsoCodes: "as" # American Samoa
+>
+
+mobile_countries:<
+    mcc: "545"
+    countryIsoCodes: "ki" # Kiribati (Republic of)
+>
+
+mobile_countries:<
+    mcc: "546"
+    countryIsoCodes: "nc" # New Caledonia
+>
+
+mobile_countries:<
+    mcc: "547"
+    countryIsoCodes: "pf" # French Polynesia
+>
+
+mobile_countries:<
+    mcc: "548"
+    countryIsoCodes: "ck" # Cook Islands
+>
+
+mobile_countries:<
+    mcc: "549"
+    countryIsoCodes: "ws" # Samoa (Independent State of)
+>
+
+mobile_countries:<
+    mcc: "550"
+    countryIsoCodes: "fm" # Micronesia (Federated States of)
+>
+
+mobile_countries:<
+    mcc: "551"
+    countryIsoCodes: "mh" # Marshall Islands (Republic of the)
+>
+
+mobile_countries:<
+    mcc: "552"
+    countryIsoCodes: "pw" # Palau (Republic of)
+>
+
+mobile_countries:<
+    mcc: "553"
+    countryIsoCodes: "tv" # Tuvalu
+>
+
+mobile_countries:<
+    mcc: "554"
+    countryIsoCodes: "tk" # Tokelau
+>
+
+mobile_countries:<
+    mcc: "555"
+    countryIsoCodes: "nu" # Niue
+>
+
+mobile_countries:<
+    mcc: "602"
+    countryIsoCodes: "eg" # Egypt (Arab Republic of)
+>
+
+mobile_countries:<
+    mcc: "603"
+    countryIsoCodes: "dz" # Algeria (People's Democratic Republic of)
+>
+
+mobile_countries:<
+    mcc: "604"
+    countryIsoCodes: "ma" # Morocco (Kingdom of)
+>
+
+mobile_countries:<
+    mcc: "605"
+    countryIsoCodes: "tn" # Tunisia
+>
+
+mobile_countries:<
+    mcc: "606"
+    countryIsoCodes: "ly" # Libya
+>
+
+mobile_countries:<
+    mcc: "607"
+    countryIsoCodes: "gm" # Gambia (Republic of the)
+>
+
+mobile_countries:<
+    mcc: "608"
+    countryIsoCodes: "sn" # Senegal (Republic of)
+>
+
+mobile_countries:<
+    mcc: "609"
+    countryIsoCodes: "mr" # Mauritania (Islamic Republic of)
+>
+
+mobile_countries:<
+    mcc: "610"
+    countryIsoCodes: "ml" # Mali (Republic of)
+>
+
+mobile_countries:<
+    mcc: "611"
+    countryIsoCodes: "gn" # Guinea (Republic of)
+>
+
+mobile_countries:<
+    mcc: "612"
+    countryIsoCodes: "ci" # Côte d'Ivoire (Republic of)
+>
+
+mobile_countries:<
+    mcc: "613"
+    countryIsoCodes: "bf" # Burkina Faso
+>
+
+mobile_countries:<
+    mcc: "614"
+    countryIsoCodes: "ne" # Niger (Republic of the)
+>
+
+mobile_countries:<
+    mcc: "615"
+    countryIsoCodes: "tg" # Togolese Republic
+>
+
+mobile_countries:<
+    mcc: "616"
+    countryIsoCodes: "bj" # Benin (Republic of)
+>
+
+mobile_countries:<
+    mcc: "617"
+    countryIsoCodes: "mu" # Mauritius (Republic of)
+>
+
+mobile_countries:<
+    mcc: "618"
+    countryIsoCodes: "lr" # Liberia (Republic of)
+>
+
+mobile_countries:<
+    mcc: "619"
+    countryIsoCodes: "sl" # Sierra Leone
+>
+
+mobile_countries:<
+    mcc: "620"
+    countryIsoCodes: "gh" # Ghana
+>
+
+mobile_countries:<
+    mcc: "621"
+    countryIsoCodes: "ng" # Nigeria (Federal Republic of)
+>
+
+mobile_countries:<
+    mcc: "622"
+    countryIsoCodes: "td" # Chad (Republic of)
+>
+
+mobile_countries:<
+    mcc: "623"
+    countryIsoCodes: "cf" # Central African Republic
+>
+
+mobile_countries:<
+    mcc: "624"
+    countryIsoCodes: "cm" # Cameroon (Republic of)
+>
+
+mobile_countries:<
+    mcc: "625"
+    countryIsoCodes: "cv" # Cape Verde (Republic of)
+>
+
+mobile_countries:<
+    mcc: "626"
+    countryIsoCodes: "st" # Sao Tome and Principe (Democratic Republic of)
+>
+
+mobile_countries:<
+    mcc: "627"
+    countryIsoCodes: "gq" # Equatorial Guinea (Republic of)
+>
+
+mobile_countries:<
+    mcc: "628"
+    countryIsoCodes: "ga" # Gabonese Republic
+>
+
+mobile_countries:<
+    mcc: "629"
+    countryIsoCodes: "cg" # Congo (Republic of the)
+>
+
+mobile_countries:<
+    mcc: "630"
+    countryIsoCodes: "cd" # Democratic Republic of the Congo
+>
+
+mobile_countries:<
+    mcc: "631"
+    countryIsoCodes: "ao" # Angola (Republic of)
+>
+
+mobile_countries:<
+    mcc: "632"
+    countryIsoCodes: "gw" # Guinea-Bissau (Republic of)
+>
+
+mobile_countries:<
+    mcc: "633"
+    countryIsoCodes: "sc" # Seychelles (Republic of)
+>
+
+mobile_countries:<
+    mcc: "634"
+    countryIsoCodes: "sd" # Sudan (Republic of the)
+>
+
+mobile_countries:<
+    mcc: "635"
+    countryIsoCodes: "rw" # Rwanda (Republic of)
+>
+
+mobile_countries:<
+    mcc: "636"
+    countryIsoCodes: "et" # Ethiopia (Federal Democratic Republic of)
+>
+
+mobile_countries:<
+    mcc: "637"
+    countryIsoCodes: "so" # Somali Democratic Republic
+>
+
+mobile_countries:<
+    mcc: "638"
+    countryIsoCodes: "dj" # Djibouti (Republic of)
+>
+
+mobile_countries:<
+    mcc: "639"
+    countryIsoCodes: "ke" # Kenya (Republic of)
+>
+
+mobile_countries:<
+    mcc: "640"
+    countryIsoCodes: "tz" # Tanzania (United Republic of)
+>
+
+mobile_countries:<
+    mcc: "641"
+    countryIsoCodes: "ug" # Uganda (Republic of)
+>
+
+mobile_countries:<
+    mcc: "642"
+    countryIsoCodes: "bi" # Burundi (Republic of)
+>
+
+mobile_countries:<
+    mcc: "643"
+    countryIsoCodes: "mz" # Mozambique (Republic of)
+>
+
+mobile_countries:<
+    mcc: "645"
+    countryIsoCodes: "zm" # Zambia (Republic of)
+>
+
+mobile_countries:<
+    mcc: "646"
+    countryIsoCodes: "mg" # Madagascar (Republic of)
+>
+
+mobile_countries:<
+    mcc: "647"
+    countryIsoCodes: "re" # Default: Reunion
+
+    countryIsoCodes: "yt" # Mayotte
+>
+
+mobile_countries:<
+    mcc: "648"
+    countryIsoCodes: "zw" # Zimbabwe (Republic of)
+>
+
+mobile_countries:<
+    mcc: "649"
+    countryIsoCodes: "na" # Namibia (Republic of)
+>
+
+mobile_countries:<
+    mcc: "650"
+    countryIsoCodes: "mw" # Malawi
+>
+
+mobile_countries:<
+    mcc: "651"
+    countryIsoCodes: "ls" # Lesotho (Kingdom of)
+>
+
+mobile_countries:<
+    mcc: "652"
+    countryIsoCodes: "bw" # Botswana (Republic of)
+>
+
+mobile_countries:<
+    mcc: "653"
+    countryIsoCodes: "sz" # Swaziland (Kingdom of)
+>
+
+mobile_countries:<
+    mcc: "654"
+    countryIsoCodes: "km" # Comoros (Union of the)
+>
+
+mobile_countries:<
+    mcc: "655"
+    countryIsoCodes: "za" # South Africa (Republic of)
+>
+
+mobile_countries:<
+    mcc: "657"
+    countryIsoCodes: "er" # Eritrea
+>
+
+mobile_countries:<
+    mcc: "658"
+    countryIsoCodes: "sh" # Saint Helena, Ascension and Tristan da Cunha
+>
+
+mobile_countries:<
+    mcc: "659"
+    countryIsoCodes: "ss" # South Sudan (Republic of)
+>
+
+mobile_countries:<
+    mcc: "702"
+    countryIsoCodes: "bz" # Belize
+>
+
+mobile_countries:<
+    mcc: "704"
+    countryIsoCodes: "gt" # Guatemala (Republic of)
+>
+
+mobile_countries:<
+    mcc: "706"
+    countryIsoCodes: "sv" # El Salvador (Republic of)
+>
+
+mobile_countries:<
+    mcc: "708"
+    countryIsoCodes: "hn" # Honduras (Republic of)
+>
+
+mobile_countries:<
+    mcc: "710"
+    countryIsoCodes: "ni" # Nicaragua
+>
+
+mobile_countries:<
+    mcc: "712"
+    countryIsoCodes: "cr" # Costa Rica
+>
+
+mobile_countries:<
+    mcc: "714"
+    countryIsoCodes: "pa" # Panama (Republic of)
+>
+
+mobile_countries:<
+    mcc: "716"
+    countryIsoCodes: "pe" # Peru
+>
+
+mobile_countries:<
+    mcc: "722"
+    countryIsoCodes: "ar" # Argentine Republic
+>
+
+mobile_countries:<
+    mcc: "724"
+    countryIsoCodes: "br" # Brazil (Federative Republic of)
+>
+
+mobile_countries:<
+    mcc: "730"
+    countryIsoCodes: "cl" # Chile
+>
+
+mobile_countries:<
+    mcc: "732"
+    countryIsoCodes: "co" # Colombia (Republic of)
+>
+
+mobile_countries:<
+    mcc: "734"
+    countryIsoCodes: "ve" # Venezuela (Bolivarian Republic of)
+>
+
+mobile_countries:<
+    mcc: "736"
+    countryIsoCodes: "bo" # Bolivia (Republic of)
+>
+
+mobile_countries:<
+    mcc: "738"
+    countryIsoCodes: "gy" # Guyana
+>
+
+mobile_countries:<
+    mcc: "740"
+    countryIsoCodes: "ec" # Ecuador
+>
+
+mobile_countries:<
+    mcc: "742"
+    countryIsoCodes: "gf" # French Guiana
+>
+
+mobile_countries:<
+    mcc: "744"
+    countryIsoCodes: "py" # Paraguay (Republic of)
+>
+
+mobile_countries:<
+    mcc: "746"
+    countryIsoCodes: "sr" # Suriname (Republic of)
+>
+
+mobile_countries:<
+    mcc: "748"
+    countryIsoCodes: "uy" # Uruguay (Eastern Republic of)
+>
+
+mobile_countries:<
+    mcc: "750"
+    countryIsoCodes: "fk" # Falkland Islands (Malvinas)
+>
diff --git a/input_tools/android/telephonylookup_generator/src/main/java/com/android/libcore/timezone/telephonylookup/TelephonyLookupGenerator.java b/input_tools/android/telephonylookup_generator/src/main/java/com/android/libcore/timezone/telephonylookup/TelephonyLookupGenerator.java
index 4626d8d..cdb1e98 100644
--- a/input_tools/android/telephonylookup_generator/src/main/java/com/android/libcore/timezone/telephonylookup/TelephonyLookupGenerator.java
+++ b/input_tools/android/telephonylookup_generator/src/main/java/com/android/libcore/timezone/telephonylookup/TelephonyLookupGenerator.java
@@ -80,12 +80,17 @@ public final class TelephonyLookupGenerator {
             }
 
             List<TelephonyLookupProtoFile.Network> networksIn = telephonyLookupIn.getNetworksList();
+            List<TelephonyLookupProtoFile.MobileCountry> mobileCountriesIn =
+                telephonyLookupIn.getMobileCountriesList();
 
             validateNetworks(networksIn, errors);
             errors.throwIfError("One or more validation errors encountered");
 
+            validateMobileCountries(mobileCountriesIn, errors);
+            errors.throwIfError("One or more validation errors encountered");
+
             TelephonyLookupXmlFile.TelephonyLookup telephonyLookupOut =
-                    createOutputTelephonyLookup(networksIn);
+                    createOutputTelephonyLookup(networksIn, mobileCountriesIn);
             logInfo("Writing " + outputFile);
             try {
                 TelephonyLookupXmlFile.write(telephonyLookupOut, outputFile);
@@ -141,6 +146,48 @@ public final class TelephonyLookupGenerator {
         }
     }
 
+    private static void validateMobileCountries(
+            List<TelephonyLookupProtoFile.MobileCountry> mobileCountriesIn,
+            Errors errors) {
+        errors.pushScope("validateMobileCountries");
+        try {
+            Set<String> knownIsoCountries = getLowerCaseCountryIsoCodes();
+            Set<String> mccSet = new HashSet<>();
+
+            if (mobileCountriesIn.isEmpty()) {
+                errors.addError("No mobile countries found");
+            }
+
+            for (TelephonyLookupProtoFile.MobileCountry mobileCountryIn : mobileCountriesIn) {
+                String mcc = mobileCountryIn.getMcc();
+                if (mcc.length() != 3 || !isAsciiNumeric(mcc)) {
+                    errors.addError("mcc=" + mcc + " must have 3 decimal digits");
+                }
+
+                if (!mccSet.add(mcc)) {
+                    errors.addError("Duplicate entry for mcc=" + mcc);
+                }
+
+                if (mobileCountryIn.getCountryIsoCodesList().isEmpty()) {
+                    errors.addError("Missing countries for mcc=" + mcc);
+                }
+
+                for (String countryIsoCode : mobileCountryIn.getCountryIsoCodesList()) {
+                    String countryIsoCodeLower = countryIsoCode.toLowerCase(Locale.ROOT);
+                    if (!countryIsoCodeLower.equals(countryIsoCode)) {
+                        errors.addError("Country code not lower case: " + countryIsoCode);
+                    }
+
+                    if (!knownIsoCountries.contains(countryIsoCodeLower)) {
+                        errors.addError("Country code not known: " + countryIsoCode);
+                    }
+                }
+            }
+        } finally {
+            errors.popScope();
+        }
+    }
+
     private static boolean isAsciiNumeric(String string) {
         for (int i = 0; i < string.length(); i++) {
             char character = string.charAt(i);
@@ -161,7 +208,9 @@ public final class TelephonyLookupGenerator {
     }
 
     private static TelephonyLookupXmlFile.TelephonyLookup createOutputTelephonyLookup(
-            List<TelephonyLookupProtoFile.Network> networksIn) {
+            List<TelephonyLookupProtoFile.Network> networksIn,
+            List<TelephonyLookupProtoFile.MobileCountry> mobileCountriesIn) {
+        // Networks
         List<TelephonyLookupXmlFile.Network> networksOut = new ArrayList<>();
         for (TelephonyLookupProtoFile.Network networkIn : networksIn) {
             String mcc = networkIn.getMcc();
@@ -171,7 +220,17 @@ public final class TelephonyLookupGenerator {
                     new TelephonyLookupXmlFile.Network(mcc, mnc, countryIsoCode);
             networksOut.add(networkOut);
         }
-        return new TelephonyLookupXmlFile.TelephonyLookup(networksOut);
+
+        // Mobile Countries
+        List<TelephonyLookupXmlFile.MobileCountry> mobileCountriesOut = new ArrayList<>();
+        for (TelephonyLookupProtoFile.MobileCountry mobileCountryIn : mobileCountriesIn) {
+            TelephonyLookupXmlFile.MobileCountry mobileCountryOut =
+                    new TelephonyLookupXmlFile.MobileCountry(
+                            mobileCountryIn.getMcc(), mobileCountryIn.getCountryIsoCodesList());
+            mobileCountriesOut.add(mobileCountryOut);
+        }
+
+        return new TelephonyLookupXmlFile.TelephonyLookup(networksOut, mobileCountriesOut);
     }
 
     private static void logError(String msg) {
diff --git a/input_tools/android/telephonylookup_generator/src/main/java/com/android/libcore/timezone/telephonylookup/TelephonyLookupXmlFile.java b/input_tools/android/telephonylookup_generator/src/main/java/com/android/libcore/timezone/telephonylookup/TelephonyLookupXmlFile.java
index 04b8561..3a79947 100644
--- a/input_tools/android/telephonylookup_generator/src/main/java/com/android/libcore/timezone/telephonylookup/TelephonyLookupXmlFile.java
+++ b/input_tools/android/telephonylookup_generator/src/main/java/com/android/libcore/timezone/telephonylookup/TelephonyLookupXmlFile.java
@@ -52,6 +52,13 @@ final class TelephonyLookupXmlFile {
     private static final String MOBILE_NETWORK_CODE_ATTRIBUTE = "mnc";
     private static final String COUNTRY_ISO_CODE_ATTRIBUTE = "country";
 
+    // <mobile_countries>
+    private static final String MOBILE_COUNTRIES_ELEMENT = "mobile_countries";
+
+    // <mobile_country mcc="123" [default="gu"]>
+    private static final String MOBILE_COUNTRY_ELEMENT = "mobile_country";
+    private static final String DEFAULT_ATTRIBUTE = "default";
+
     static void write(TelephonyLookup telephonyLookup, String outputFile)
             throws XMLStreamException, IOException {
         /*
@@ -60,8 +67,17 @@ final class TelephonyLookupXmlFile {
          *   <networks>
          *     <network mcc="123" mnc="456" country="zz"/>
          *     <network mcc="123" mnc="789" country="zz"/>
-         *     </network>
          *   </networks>
+         *
+         *   <mobile_countries>
+         *     <mobile_country mcc="310"/>
+         *       <country>us</country>
+         *     </mobile_country>
+         *     <mobile_country mcc="340" default="gp">
+         *       <country>gp</country>
+         *       <country>gf</country>
+         *     </mobile_country>
+         *   </mobile_countries>
          * </telephony_lookup>
          */
 
@@ -97,19 +113,31 @@ final class TelephonyLookupXmlFile {
 
     static class TelephonyLookup {
         private final List<Network> networks;
+        private final List<MobileCountry> mobileCountries;
 
-        TelephonyLookup(List<Network> networks) {
+        TelephonyLookup(List<Network> networks, List<MobileCountry> mobileCountries) {
             this.networks = networks;
+            this.mobileCountries = mobileCountries;
         }
 
         static void writeXml(TelephonyLookup telephonyLookup, XMLStreamWriter writer)
                 throws XMLStreamException {
             writer.writeStartElement(TELEPHONY_LOOKUP_ELEMENT);
+
+            // Networks
             writer.writeStartElement(NETWORKS_ELEMENT);
             for (Network network : telephonyLookup.networks) {
                 network.writeXml(network, writer);
             }
             writer.writeEndElement(); // NETWORKS_ELEMENT
+
+            // Mobile Countries
+            writer.writeStartElement(MOBILE_COUNTRIES_ELEMENT);
+            for (MobileCountry mobileCountry : telephonyLookup.mobileCountries) {
+                mobileCountry.writeXml(mobileCountry, writer);
+            }
+            writer.writeEndElement(); // MOBILE_COUNTRIES_ELEMENT
+
             writer.writeEndElement(); // TELEPHONY_LOOKUP_ELEMENT
         }
     }
@@ -135,4 +163,33 @@ final class TelephonyLookupXmlFile {
             writer.writeEndElement(); // NETWORK_ELEMENT
         }
     }
+
+    static class MobileCountry {
+
+        private final String mcc;
+        private final List<String> countryIsoCodes;
+
+        MobileCountry(String mcc, List<String> countryIsoCodes) {
+            this.mcc = Objects.requireNonNull(mcc);
+            this.countryIsoCodes = Objects.requireNonNull(countryIsoCodes);
+        }
+
+        static void writeXml(MobileCountry mobileCountry, XMLStreamWriter writer)
+                throws XMLStreamException {
+            writer.writeStartElement(MOBILE_COUNTRY_ELEMENT);
+            writer.writeAttribute(MOBILE_COUNTRY_CODE_ATTRIBUTE, mobileCountry.mcc);
+
+            if (mobileCountry.countryIsoCodes.size() > 1) {
+                writer.writeAttribute(DEFAULT_ATTRIBUTE, mobileCountry.countryIsoCodes.getFirst());
+            }
+
+            for (String countryIsoCode : mobileCountry.countryIsoCodes) {
+                writer.writeStartElement(COUNTRY_ISO_CODE_ATTRIBUTE);
+                writer.writeCharacters(countryIsoCode);
+                writer.writeEndElement(); // COUNTRY_ISO_CODE_ATTRIBUTE
+            }
+
+            writer.writeEndElement(); // MOBILE_COUNTRY_ELEMENT
+        }
+    }
 }
diff --git a/input_tools/android/telephonylookup_generator/src/main/proto/telephony_lookup_proto_file.proto b/input_tools/android/telephonylookup_generator/src/main/proto/telephony_lookup_proto_file.proto
index 661e3d3..18d210c 100644
--- a/input_tools/android/telephonylookup_generator/src/main/proto/telephony_lookup_proto_file.proto
+++ b/input_tools/android/telephonylookup_generator/src/main/proto/telephony_lookup_proto_file.proto
@@ -22,7 +22,10 @@ option java_multiple_files = false;
 package com.android.libcore.timezone.telephonylookup.proto;
 
 message TelephonyLookup {
+    /* MCC/MNC override for a specific region */
     repeated Network networks = 1;
+    /* Countries of a given MCC */
+    repeated MobileCountry mobile_countries = 2;
 }
 
 message Network {
@@ -30,6 +33,13 @@ message Network {
     required string mcc = 1;
     /* A 2- or 3-digit numeric in ASCII. */
     required string mnc = 2;
-    /* An ISO 3166 alpha-2 code (lower case).  */
+    /* An ISO 3166 alpha-2 code (lower case). */
     required string countryIsoCode = 3;
 }
+
+message MobileCountry {
+    /* A 3-digit numeric in ASCII. */
+    required string mcc = 1;
+    /* ISO 3166 alpha-2 codes (lower case). */
+    repeated string countryIsoCodes = 2;
+}
\ No newline at end of file
diff --git a/input_tools/android/telephonylookup_generator/src/test/java/com/android/libcore/timezone/telephonylookup/TelephonyLookupGeneratorTest.java b/input_tools/android/telephonylookup_generator/src/test/java/com/android/libcore/timezone/telephonylookup/TelephonyLookupGeneratorTest.java
index d07833b..16b38a8 100644
--- a/input_tools/android/telephonylookup_generator/src/test/java/com/android/libcore/timezone/telephonylookup/TelephonyLookupGeneratorTest.java
+++ b/input_tools/android/telephonylookup_generator/src/test/java/com/android/libcore/timezone/telephonylookup/TelephonyLookupGeneratorTest.java
@@ -18,12 +18,17 @@ package com.android.libcore.timezone.telephonylookup;
 
 import static com.android.libcore.timezone.testing.TestUtils.assertContains;
 import static com.android.libcore.timezone.testing.TestUtils.createFile;
+
 import static junit.framework.Assert.assertEquals;
+
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertTrue;
 
-import com.android.libcore.timezone.telephonylookup.proto.TelephonyLookupProtoFile;
+import com.android.libcore.timezone.telephonylookup.proto.TelephonyLookupProtoFile.MobileCountry;
+import com.android.libcore.timezone.telephonylookup.proto.TelephonyLookupProtoFile.Network;
+import com.android.libcore.timezone.telephonylookup.proto.TelephonyLookupProtoFile.TelephonyLookup;
 import com.android.libcore.timezone.testing.TestUtils;
+
 import com.google.protobuf.TextFormat;
 
 import org.junit.After;
@@ -35,6 +40,8 @@ import java.nio.charset.StandardCharsets;
 import java.nio.file.Files;
 import java.nio.file.Path;
 import java.nio.file.Paths;
+import java.util.List;
+import java.util.stream.Collectors;
 
 public class TelephonyLookupGeneratorTest {
 
@@ -63,80 +70,120 @@ public class TelephonyLookupGeneratorTest {
     }
 
     @Test
-    public void upperCaseCountryIsoCodeIsRejected() throws Exception {
-        TelephonyLookupProtoFile.Network network = createNetwork("123", "456", "GB");
-        checkGenerationFails(createTelephonyLookup(network));
+    public void networks_upperCaseCountryIsoCodeIsRejected() throws Exception {
+        Network network = createNetwork("123", "456", "GB");
+        checkGenerationFails(createTelephonyLookup(List.of(network), List.of()));
     }
 
     @Test
-    public void unknownCountryIsoCodeIsRejected() throws Exception {
-        TelephonyLookupProtoFile.Network network = createNetwork("123", "456", "zx");
-        checkGenerationFails(createTelephonyLookup(network));
+    public void networks_unknownCountryIsoCodeIsRejected() throws Exception {
+        Network network = createNetwork("123", "456", "zx");
+        checkGenerationFails(createTelephonyLookup(List.of(network), List.of()));
     }
 
     @Test
-    public void badMccIsRejected_nonNumeric() throws Exception {
-        TelephonyLookupProtoFile.Network network = createNetwork("XXX", "456", "gb");
-        checkGenerationFails(createTelephonyLookup(network));
+    public void networks_badMccIsRejected_nonNumeric() throws Exception {
+        Network network = createNetwork("XXX", "456", "gb");
+        checkGenerationFails(createTelephonyLookup(List.of(network), List.of()));
     }
 
     @Test
-    public void badMccIsRejected_tooShort() throws Exception {
-        TelephonyLookupProtoFile.Network network = createNetwork("12", "456", "gb");
-        checkGenerationFails(createTelephonyLookup(network));
+    public void networks_badMccIsRejected_tooShort() throws Exception {
+        Network network = createNetwork("12", "456", "gb");
+        checkGenerationFails(createTelephonyLookup(List.of(network), List.of()));
     }
 
     @Test
-    public void badMccIsRejected_tooLong() throws Exception {
-        TelephonyLookupProtoFile.Network network = createNetwork("1234", "567", "gb");
-        checkGenerationFails(createTelephonyLookup(network));
+    public void networks_badMccIsRejected_tooLong() throws Exception {
+        Network network = createNetwork("1234", "567", "gb");
+        checkGenerationFails(createTelephonyLookup(List.of(network), List.of()));
     }
 
     @Test
-    public void badMncIsRejected_nonNumeric() throws Exception {
-        TelephonyLookupProtoFile.Network network = createNetwork("123", "XXX", "gb");
-        checkGenerationFails(createTelephonyLookup(network));
+    public void networks_badMncIsRejected_nonNumeric() throws Exception {
+        Network network = createNetwork("123", "XXX", "gb");
+        checkGenerationFails(createTelephonyLookup(List.of(network), List.of()));
     }
 
     @Test
-    public void badMncIsRejected_tooShort() throws Exception {
-        TelephonyLookupProtoFile.Network network = createNetwork("123", "4", "gb");
-        checkGenerationFails(createTelephonyLookup(network));
+    public void networks_badMncIsRejected_tooShort() throws Exception {
+        Network network = createNetwork("123", "4", "gb");
+        checkGenerationFails(createTelephonyLookup(List.of(network), List.of()));
     }
 
     @Test
-    public void badMncIsRejected_tooLong() throws Exception {
-        TelephonyLookupProtoFile.Network network = createNetwork("123", "4567", "gb");
-        checkGenerationFails(createTelephonyLookup(network));
+    public void networks_badMncIsRejected_tooLong() throws Exception {
+        Network network = createNetwork("123", "4567", "gb");
+        checkGenerationFails(createTelephonyLookup(List.of(network), List.of()));
     }
 
     @Test
-    public void duplicateMccMncComboIsRejected() throws Exception {
-        TelephonyLookupProtoFile.Network network1 = createNetwork("123", "456", "gb");
-        TelephonyLookupProtoFile.Network network2 = createNetwork("123", "456", "us");
-        checkGenerationFails(createTelephonyLookup(network1, network2));
+    public void networks_duplicateMccMncComboIsRejected() throws Exception {
+        Network network1 = createNetwork("123", "456", "gb");
+        Network network2 = createNetwork("123", "456", "us");
+        checkGenerationFails(createTelephonyLookup(List.of(network1, network2), List.of()));
     }
 
     @Test
-    public void validDataCreatesFile() throws Exception {
-        TelephonyLookupProtoFile.Network network1 = createNetwork("123", "456", "gb");
-        TelephonyLookupProtoFile.Network network2 = createNetwork("123", "56", "us");
-        TelephonyLookupProtoFile.TelephonyLookup telephonyLookupProto =
-                createTelephonyLookup(network1, network2);
+    public void mobileCountries_upperCaseCountryIsoCodeIsRejected() throws Exception {
+        MobileCountry mobileCountry = createMobileCountry("123", List.of("GB"));
+        checkGenerationFails(createTelephonyLookup(List.of(), List.of(mobileCountry)));
+    }
 
-        String telephonyLookupXml = generateTelephonyLookupXml(telephonyLookupProto);
-        assertContains(telephonyLookupXml,
-                "<network mcc=\"123\" mnc=\"456\" country=\"gb\"/>",
-                "<network mcc=\"123\" mnc=\"56\" country=\"us\"/>"
-        );
+    @Test
+    public void mobileCountries_unknownCountryIsoCodeIsRejected() throws Exception {
+        MobileCountry mobileCountry = createMobileCountry("123", List.of("gb", "zx"));
+        checkGenerationFails(createTelephonyLookup(List.of(), List.of(mobileCountry)));
+    }
 
+    @Test
+    public void mobileCountries_badMccIsRejected_nonNumeric() throws Exception {
+        MobileCountry mobileCountry = createMobileCountry("XXX", List.of("gb"));
+        checkGenerationFails(createTelephonyLookup(List.of(), List.of(mobileCountry)));
+    }
+
+    @Test
+    public void mobileCountries_badMccIsRejected_tooShort() throws Exception {
+        MobileCountry mobileCountry = createMobileCountry("12", List.of("gb"));
+        checkGenerationFails(createTelephonyLookup(List.of(), List.of(mobileCountry)));
     }
 
+    @Test
+    public void mobileCountries_badMccIsRejected_tooLong() throws Exception {
+        MobileCountry mobileCountry = createMobileCountry("1234", List.of("gb"));
+        checkGenerationFails(createTelephonyLookup(List.of(), List.of(mobileCountry)));
+    }
 
-    private void checkGenerationFails(TelephonyLookupProtoFile.TelephonyLookup telephonyLookup2)
+    @Test
+    public void mobileCountries_duplicateMccComboIsRejected() throws Exception {
+        MobileCountry mobileCountry1 = createMobileCountry("123", List.of("gb"));
+        MobileCountry mobileCountry2 = createMobileCountry("123", List.of("gb"));
+        checkGenerationFails(
+                createTelephonyLookup(List.of(), List.of(mobileCountry1, mobileCountry2)));
+    }
+
+    @Test
+    public void validDataCreatesFile() throws Exception {
+        Network network1 = createNetwork("123", "456", "gb");
+        Network network2 = createNetwork("123", "56", "us");
+        MobileCountry mobileCountry1 = createMobileCountry("123", List.of("gb"));
+        MobileCountry mobileCountry2 = createMobileCountry("456", List.of("us", "fr"));
+        TelephonyLookup telephonyLookupProto =
+                createTelephonyLookup(List.of(network1, network2),
+                        List.of(mobileCountry1, mobileCountry2));
+
+        String telephonyLookupXml = generateTelephonyLookupXml(telephonyLookupProto);
+    assertContains(
+        trimAndLinearize(telephonyLookupXml),
+        "<network mcc=\"123\" mnc=\"456\" country=\"gb\"/>",
+        "<network mcc=\"123\" mnc=\"56\" country=\"us\"/>",
+        "<mobile_country mcc=\"123\"><country>gb</country></mobile_country>",
+        "<mobile_country mcc=\"456\""
+            + " default=\"us\"><country>us</country><country>fr</country></mobile_country>");
+    }
+
+    private void checkGenerationFails(TelephonyLookup telephonyLookup)
             throws Exception {
-        TelephonyLookupProtoFile.TelephonyLookup telephonyLookup =
-                telephonyLookup2;
         String telephonyLookupFile = createTelephonyLookupFile(telephonyLookup);
         String outputFile = Files.createTempFile(tempDir, "out", null /* suffix */).toString();
 
@@ -148,13 +195,12 @@ public class TelephonyLookupGeneratorTest {
     }
 
     private String createTelephonyLookupFile(
-            TelephonyLookupProtoFile.TelephonyLookup telephonyLookup) throws Exception {
+            TelephonyLookup telephonyLookup) throws Exception {
         return TestUtils.createFile(tempDir, TextFormat.printToString(telephonyLookup));
     }
 
     private String generateTelephonyLookupXml(
-            TelephonyLookupProtoFile.TelephonyLookup telephonyLookup) throws Exception {
-
+            TelephonyLookup telephonyLookup) throws Exception {
         String telephonyLookupFile = createTelephonyLookupFile(telephonyLookup);
 
         String outputFile = Files.createTempFile(tempDir, "out", null /* suffix */).toString();
@@ -173,27 +219,37 @@ public class TelephonyLookupGeneratorTest {
         return new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
     }
 
-    private static TelephonyLookupProtoFile.Network createNetwork(String mcc, String mnc,
+    private static Network createNetwork(String mcc, String mnc,
             String isoCountryCode) {
-        return TelephonyLookupProtoFile.Network.newBuilder()
+        return Network.newBuilder()
                 .setMcc(mcc)
                 .setMnc(mnc)
                 .setCountryIsoCode(isoCountryCode)
                 .build();
     }
 
-    private static TelephonyLookupProtoFile.TelephonyLookup createTelephonyLookup(
-            TelephonyLookupProtoFile.Network... networks) {
-        TelephonyLookupProtoFile.TelephonyLookup.Builder builder =
-                TelephonyLookupProtoFile.TelephonyLookup.newBuilder();
-        for (TelephonyLookupProtoFile.Network network : networks) {
-            builder.addNetworks(network);
-        }
-        return builder.build();
+    private static MobileCountry createMobileCountry(
+            String mcc, List<String> countryIsoCodes) {
+        return MobileCountry.newBuilder()
+                .setMcc(mcc)
+                .addAllCountryIsoCodes(countryIsoCodes)
+                .build();
+    }
+
+    private static TelephonyLookup createTelephonyLookup(
+            List<Network> networks, List<MobileCountry> mobileCountries) {
+        return TelephonyLookup.newBuilder()
+                .addAllNetworks(networks)
+                .addAllMobileCountries(mobileCountries)
+                .build();
     }
 
     private static void assertFileIsEmpty(String outputFile) throws IOException {
         Path outputFilePath = Paths.get(outputFile);
         assertEquals(0, Files.size(outputFilePath));
     }
+
+    private static String trimAndLinearize(String input) {
+        return input.lines().map(String::trim).collect(Collectors.joining());
+    }
 }
diff --git a/output_data/android/telephonylookup.xml b/output_data/android/telephonylookup.xml
index 17a7e9c..6582955 100644
--- a/output_data/android/telephonylookup.xml
+++ b/output_data/android/telephonylookup.xml
@@ -8,4 +8,732 @@
   <network mcc="310" mnc="470" country="gu"/>
   <network mcc="311" mnc="780" country="as"/>
  </networks>
+ <mobile_countries>
+  <mobile_country mcc="202">
+   <country>gr</country>
+  </mobile_country>
+  <mobile_country mcc="204">
+   <country>nl</country>
+  </mobile_country>
+  <mobile_country mcc="206">
+   <country>be</country>
+  </mobile_country>
+  <mobile_country mcc="208">
+   <country>fr</country>
+  </mobile_country>
+  <mobile_country mcc="212">
+   <country>mc</country>
+  </mobile_country>
+  <mobile_country mcc="213">
+   <country>ad</country>
+  </mobile_country>
+  <mobile_country mcc="214">
+   <country>es</country>
+  </mobile_country>
+  <mobile_country mcc="216">
+   <country>hu</country>
+  </mobile_country>
+  <mobile_country mcc="218">
+   <country>ba</country>
+  </mobile_country>
+  <mobile_country mcc="219">
+   <country>hr</country>
+  </mobile_country>
+  <mobile_country mcc="220">
+   <country>rs</country>
+  </mobile_country>
+  <mobile_country mcc="221">
+   <country>xk</country>
+  </mobile_country>
+  <mobile_country mcc="222">
+   <country>it</country>
+  </mobile_country>
+  <mobile_country mcc="225">
+   <country>va</country>
+  </mobile_country>
+  <mobile_country mcc="226">
+   <country>ro</country>
+  </mobile_country>
+  <mobile_country mcc="228">
+   <country>ch</country>
+  </mobile_country>
+  <mobile_country mcc="230">
+   <country>cz</country>
+  </mobile_country>
+  <mobile_country mcc="231">
+   <country>sk</country>
+  </mobile_country>
+  <mobile_country mcc="232">
+   <country>at</country>
+  </mobile_country>
+  <mobile_country mcc="234">
+   <country>gb</country>
+  </mobile_country>
+  <mobile_country mcc="235">
+   <country>gb</country>
+  </mobile_country>
+  <mobile_country mcc="238">
+   <country>dk</country>
+  </mobile_country>
+  <mobile_country mcc="240">
+   <country>se</country>
+  </mobile_country>
+  <mobile_country mcc="242">
+   <country>no</country>
+  </mobile_country>
+  <mobile_country mcc="244">
+   <country>fi</country>
+  </mobile_country>
+  <mobile_country mcc="246">
+   <country>lt</country>
+  </mobile_country>
+  <mobile_country mcc="247">
+   <country>lv</country>
+  </mobile_country>
+  <mobile_country mcc="248">
+   <country>ee</country>
+  </mobile_country>
+  <mobile_country mcc="250">
+   <country>ru</country>
+  </mobile_country>
+  <mobile_country mcc="255">
+   <country>ua</country>
+  </mobile_country>
+  <mobile_country mcc="257">
+   <country>by</country>
+  </mobile_country>
+  <mobile_country mcc="259">
+   <country>md</country>
+  </mobile_country>
+  <mobile_country mcc="260">
+   <country>pl</country>
+  </mobile_country>
+  <mobile_country mcc="262">
+   <country>de</country>
+  </mobile_country>
+  <mobile_country mcc="266">
+   <country>gi</country>
+  </mobile_country>
+  <mobile_country mcc="268">
+   <country>pt</country>
+  </mobile_country>
+  <mobile_country mcc="270">
+   <country>lu</country>
+  </mobile_country>
+  <mobile_country mcc="272">
+   <country>ie</country>
+  </mobile_country>
+  <mobile_country mcc="274">
+   <country>is</country>
+  </mobile_country>
+  <mobile_country mcc="276">
+   <country>al</country>
+  </mobile_country>
+  <mobile_country mcc="278">
+   <country>mt</country>
+  </mobile_country>
+  <mobile_country mcc="280">
+   <country>cy</country>
+  </mobile_country>
+  <mobile_country mcc="282">
+   <country>ge</country>
+  </mobile_country>
+  <mobile_country mcc="283">
+   <country>am</country>
+  </mobile_country>
+  <mobile_country mcc="284">
+   <country>bg</country>
+  </mobile_country>
+  <mobile_country mcc="286">
+   <country>tr</country>
+  </mobile_country>
+  <mobile_country mcc="288">
+   <country>fo</country>
+  </mobile_country>
+  <mobile_country mcc="289">
+   <country>ge</country>
+  </mobile_country>
+  <mobile_country mcc="290">
+   <country>gl</country>
+  </mobile_country>
+  <mobile_country mcc="292">
+   <country>sm</country>
+  </mobile_country>
+  <mobile_country mcc="293">
+   <country>si</country>
+  </mobile_country>
+  <mobile_country mcc="294">
+   <country>mk</country>
+  </mobile_country>
+  <mobile_country mcc="295">
+   <country>li</country>
+  </mobile_country>
+  <mobile_country mcc="297">
+   <country>me</country>
+  </mobile_country>
+  <mobile_country mcc="302">
+   <country>ca</country>
+  </mobile_country>
+  <mobile_country mcc="308">
+   <country>pm</country>
+  </mobile_country>
+  <mobile_country mcc="310">
+   <country>us</country>
+  </mobile_country>
+  <mobile_country mcc="311">
+   <country>us</country>
+  </mobile_country>
+  <mobile_country mcc="312">
+   <country>us</country>
+  </mobile_country>
+  <mobile_country mcc="313">
+   <country>us</country>
+  </mobile_country>
+  <mobile_country mcc="314">
+   <country>us</country>
+  </mobile_country>
+  <mobile_country mcc="315">
+   <country>us</country>
+  </mobile_country>
+  <mobile_country mcc="316">
+   <country>us</country>
+  </mobile_country>
+  <mobile_country mcc="330">
+   <country>pr</country>
+  </mobile_country>
+  <mobile_country mcc="332">
+   <country>vi</country>
+  </mobile_country>
+  <mobile_country mcc="334">
+   <country>mx</country>
+  </mobile_country>
+  <mobile_country mcc="338">
+   <country>jm</country>
+  </mobile_country>
+  <mobile_country mcc="340" default="gp">
+   <country>gp</country>
+   <country>gf</country>
+  </mobile_country>
+  <mobile_country mcc="342">
+   <country>bb</country>
+  </mobile_country>
+  <mobile_country mcc="344">
+   <country>ag</country>
+  </mobile_country>
+  <mobile_country mcc="346">
+   <country>ky</country>
+  </mobile_country>
+  <mobile_country mcc="348">
+   <country>vg</country>
+  </mobile_country>
+  <mobile_country mcc="350">
+   <country>bm</country>
+  </mobile_country>
+  <mobile_country mcc="352">
+   <country>gd</country>
+  </mobile_country>
+  <mobile_country mcc="354">
+   <country>ms</country>
+  </mobile_country>
+  <mobile_country mcc="356">
+   <country>kn</country>
+  </mobile_country>
+  <mobile_country mcc="358">
+   <country>lc</country>
+  </mobile_country>
+  <mobile_country mcc="360">
+   <country>vc</country>
+  </mobile_country>
+  <mobile_country mcc="362">
+   <country>cw</country>
+  </mobile_country>
+  <mobile_country mcc="363">
+   <country>aw</country>
+  </mobile_country>
+  <mobile_country mcc="364">
+   <country>bs</country>
+  </mobile_country>
+  <mobile_country mcc="365">
+   <country>ai</country>
+  </mobile_country>
+  <mobile_country mcc="366">
+   <country>dm</country>
+  </mobile_country>
+  <mobile_country mcc="368">
+   <country>cu</country>
+  </mobile_country>
+  <mobile_country mcc="370">
+   <country>do</country>
+  </mobile_country>
+  <mobile_country mcc="372">
+   <country>ht</country>
+  </mobile_country>
+  <mobile_country mcc="374">
+   <country>tt</country>
+  </mobile_country>
+  <mobile_country mcc="376">
+   <country>tc</country>
+  </mobile_country>
+  <mobile_country mcc="400">
+   <country>az</country>
+  </mobile_country>
+  <mobile_country mcc="401">
+   <country>kz</country>
+  </mobile_country>
+  <mobile_country mcc="402">
+   <country>bt</country>
+  </mobile_country>
+  <mobile_country mcc="404">
+   <country>in</country>
+  </mobile_country>
+  <mobile_country mcc="405">
+   <country>in</country>
+  </mobile_country>
+  <mobile_country mcc="406">
+   <country>in</country>
+  </mobile_country>
+  <mobile_country mcc="410">
+   <country>pk</country>
+  </mobile_country>
+  <mobile_country mcc="412">
+   <country>af</country>
+  </mobile_country>
+  <mobile_country mcc="413">
+   <country>lk</country>
+  </mobile_country>
+  <mobile_country mcc="414">
+   <country>mm</country>
+  </mobile_country>
+  <mobile_country mcc="415">
+   <country>lb</country>
+  </mobile_country>
+  <mobile_country mcc="416">
+   <country>jo</country>
+  </mobile_country>
+  <mobile_country mcc="417">
+   <country>sy</country>
+  </mobile_country>
+  <mobile_country mcc="418">
+   <country>iq</country>
+  </mobile_country>
+  <mobile_country mcc="419">
+   <country>kw</country>
+  </mobile_country>
+  <mobile_country mcc="420">
+   <country>sa</country>
+  </mobile_country>
+  <mobile_country mcc="421">
+   <country>ye</country>
+  </mobile_country>
+  <mobile_country mcc="422">
+   <country>om</country>
+  </mobile_country>
+  <mobile_country mcc="423">
+   <country>ps</country>
+  </mobile_country>
+  <mobile_country mcc="424">
+   <country>ae</country>
+  </mobile_country>
+  <mobile_country mcc="425">
+   <country>il</country>
+  </mobile_country>
+  <mobile_country mcc="426">
+   <country>bh</country>
+  </mobile_country>
+  <mobile_country mcc="427">
+   <country>qa</country>
+  </mobile_country>
+  <mobile_country mcc="428">
+   <country>mn</country>
+  </mobile_country>
+  <mobile_country mcc="429">
+   <country>np</country>
+  </mobile_country>
+  <mobile_country mcc="430">
+   <country>ae</country>
+  </mobile_country>
+  <mobile_country mcc="431">
+   <country>ae</country>
+  </mobile_country>
+  <mobile_country mcc="432">
+   <country>ir</country>
+  </mobile_country>
+  <mobile_country mcc="434">
+   <country>uz</country>
+  </mobile_country>
+  <mobile_country mcc="436">
+   <country>tj</country>
+  </mobile_country>
+  <mobile_country mcc="437">
+   <country>kg</country>
+  </mobile_country>
+  <mobile_country mcc="438">
+   <country>tm</country>
+  </mobile_country>
+  <mobile_country mcc="440">
+   <country>jp</country>
+  </mobile_country>
+  <mobile_country mcc="441">
+   <country>jp</country>
+  </mobile_country>
+  <mobile_country mcc="450">
+   <country>kr</country>
+  </mobile_country>
+  <mobile_country mcc="452">
+   <country>vn</country>
+  </mobile_country>
+  <mobile_country mcc="454">
+   <country>hk</country>
+  </mobile_country>
+  <mobile_country mcc="455">
+   <country>mo</country>
+  </mobile_country>
+  <mobile_country mcc="456">
+   <country>kh</country>
+  </mobile_country>
+  <mobile_country mcc="457">
+   <country>la</country>
+  </mobile_country>
+  <mobile_country mcc="460">
+   <country>cn</country>
+  </mobile_country>
+  <mobile_country mcc="461">
+   <country>cn</country>
+  </mobile_country>
+  <mobile_country mcc="466">
+   <country>tw</country>
+  </mobile_country>
+  <mobile_country mcc="467">
+   <country>kp</country>
+  </mobile_country>
+  <mobile_country mcc="470">
+   <country>bd</country>
+  </mobile_country>
+  <mobile_country mcc="472">
+   <country>mv</country>
+  </mobile_country>
+  <mobile_country mcc="502">
+   <country>my</country>
+  </mobile_country>
+  <mobile_country mcc="505" default="au">
+   <country>au</country>
+   <country>nf</country>
+  </mobile_country>
+  <mobile_country mcc="510">
+   <country>id</country>
+  </mobile_country>
+  <mobile_country mcc="514">
+   <country>tl</country>
+  </mobile_country>
+  <mobile_country mcc="515">
+   <country>ph</country>
+  </mobile_country>
+  <mobile_country mcc="520">
+   <country>th</country>
+  </mobile_country>
+  <mobile_country mcc="525">
+   <country>sg</country>
+  </mobile_country>
+  <mobile_country mcc="528">
+   <country>bn</country>
+  </mobile_country>
+  <mobile_country mcc="530">
+   <country>nz</country>
+  </mobile_country>
+  <mobile_country mcc="534">
+   <country>mp</country>
+  </mobile_country>
+  <mobile_country mcc="535">
+   <country>gu</country>
+  </mobile_country>
+  <mobile_country mcc="536">
+   <country>nr</country>
+  </mobile_country>
+  <mobile_country mcc="537">
+   <country>pg</country>
+  </mobile_country>
+  <mobile_country mcc="539">
+   <country>to</country>
+  </mobile_country>
+  <mobile_country mcc="540">
+   <country>sb</country>
+  </mobile_country>
+  <mobile_country mcc="541">
+   <country>vu</country>
+  </mobile_country>
+  <mobile_country mcc="542">
+   <country>fj</country>
+  </mobile_country>
+  <mobile_country mcc="543">
+   <country>wf</country>
+  </mobile_country>
+  <mobile_country mcc="544">
+   <country>as</country>
+  </mobile_country>
+  <mobile_country mcc="545">
+   <country>ki</country>
+  </mobile_country>
+  <mobile_country mcc="546">
+   <country>nc</country>
+  </mobile_country>
+  <mobile_country mcc="547">
+   <country>pf</country>
+  </mobile_country>
+  <mobile_country mcc="548">
+   <country>ck</country>
+  </mobile_country>
+  <mobile_country mcc="549">
+   <country>ws</country>
+  </mobile_country>
+  <mobile_country mcc="550">
+   <country>fm</country>
+  </mobile_country>
+  <mobile_country mcc="551">
+   <country>mh</country>
+  </mobile_country>
+  <mobile_country mcc="552">
+   <country>pw</country>
+  </mobile_country>
+  <mobile_country mcc="553">
+   <country>tv</country>
+  </mobile_country>
+  <mobile_country mcc="554">
+   <country>tk</country>
+  </mobile_country>
+  <mobile_country mcc="555">
+   <country>nu</country>
+  </mobile_country>
+  <mobile_country mcc="602">
+   <country>eg</country>
+  </mobile_country>
+  <mobile_country mcc="603">
+   <country>dz</country>
+  </mobile_country>
+  <mobile_country mcc="604">
+   <country>ma</country>
+  </mobile_country>
+  <mobile_country mcc="605">
+   <country>tn</country>
+  </mobile_country>
+  <mobile_country mcc="606">
+   <country>ly</country>
+  </mobile_country>
+  <mobile_country mcc="607">
+   <country>gm</country>
+  </mobile_country>
+  <mobile_country mcc="608">
+   <country>sn</country>
+  </mobile_country>
+  <mobile_country mcc="609">
+   <country>mr</country>
+  </mobile_country>
+  <mobile_country mcc="610">
+   <country>ml</country>
+  </mobile_country>
+  <mobile_country mcc="611">
+   <country>gn</country>
+  </mobile_country>
+  <mobile_country mcc="612">
+   <country>ci</country>
+  </mobile_country>
+  <mobile_country mcc="613">
+   <country>bf</country>
+  </mobile_country>
+  <mobile_country mcc="614">
+   <country>ne</country>
+  </mobile_country>
+  <mobile_country mcc="615">
+   <country>tg</country>
+  </mobile_country>
+  <mobile_country mcc="616">
+   <country>bj</country>
+  </mobile_country>
+  <mobile_country mcc="617">
+   <country>mu</country>
+  </mobile_country>
+  <mobile_country mcc="618">
+   <country>lr</country>
+  </mobile_country>
+  <mobile_country mcc="619">
+   <country>sl</country>
+  </mobile_country>
+  <mobile_country mcc="620">
+   <country>gh</country>
+  </mobile_country>
+  <mobile_country mcc="621">
+   <country>ng</country>
+  </mobile_country>
+  <mobile_country mcc="622">
+   <country>td</country>
+  </mobile_country>
+  <mobile_country mcc="623">
+   <country>cf</country>
+  </mobile_country>
+  <mobile_country mcc="624">
+   <country>cm</country>
+  </mobile_country>
+  <mobile_country mcc="625">
+   <country>cv</country>
+  </mobile_country>
+  <mobile_country mcc="626">
+   <country>st</country>
+  </mobile_country>
+  <mobile_country mcc="627">
+   <country>gq</country>
+  </mobile_country>
+  <mobile_country mcc="628">
+   <country>ga</country>
+  </mobile_country>
+  <mobile_country mcc="629">
+   <country>cg</country>
+  </mobile_country>
+  <mobile_country mcc="630">
+   <country>cd</country>
+  </mobile_country>
+  <mobile_country mcc="631">
+   <country>ao</country>
+  </mobile_country>
+  <mobile_country mcc="632">
+   <country>gw</country>
+  </mobile_country>
+  <mobile_country mcc="633">
+   <country>sc</country>
+  </mobile_country>
+  <mobile_country mcc="634">
+   <country>sd</country>
+  </mobile_country>
+  <mobile_country mcc="635">
+   <country>rw</country>
+  </mobile_country>
+  <mobile_country mcc="636">
+   <country>et</country>
+  </mobile_country>
+  <mobile_country mcc="637">
+   <country>so</country>
+  </mobile_country>
+  <mobile_country mcc="638">
+   <country>dj</country>
+  </mobile_country>
+  <mobile_country mcc="639">
+   <country>ke</country>
+  </mobile_country>
+  <mobile_country mcc="640">
+   <country>tz</country>
+  </mobile_country>
+  <mobile_country mcc="641">
+   <country>ug</country>
+  </mobile_country>
+  <mobile_country mcc="642">
+   <country>bi</country>
+  </mobile_country>
+  <mobile_country mcc="643">
+   <country>mz</country>
+  </mobile_country>
+  <mobile_country mcc="645">
+   <country>zm</country>
+  </mobile_country>
+  <mobile_country mcc="646">
+   <country>mg</country>
+  </mobile_country>
+  <mobile_country mcc="647" default="re">
+   <country>re</country>
+   <country>yt</country>
+  </mobile_country>
+  <mobile_country mcc="648">
+   <country>zw</country>
+  </mobile_country>
+  <mobile_country mcc="649">
+   <country>na</country>
+  </mobile_country>
+  <mobile_country mcc="650">
+   <country>mw</country>
+  </mobile_country>
+  <mobile_country mcc="651">
+   <country>ls</country>
+  </mobile_country>
+  <mobile_country mcc="652">
+   <country>bw</country>
+  </mobile_country>
+  <mobile_country mcc="653">
+   <country>sz</country>
+  </mobile_country>
+  <mobile_country mcc="654">
+   <country>km</country>
+  </mobile_country>
+  <mobile_country mcc="655">
+   <country>za</country>
+  </mobile_country>
+  <mobile_country mcc="657">
+   <country>er</country>
+  </mobile_country>
+  <mobile_country mcc="658">
+   <country>sh</country>
+  </mobile_country>
+  <mobile_country mcc="659">
+   <country>ss</country>
+  </mobile_country>
+  <mobile_country mcc="702">
+   <country>bz</country>
+  </mobile_country>
+  <mobile_country mcc="704">
+   <country>gt</country>
+  </mobile_country>
+  <mobile_country mcc="706">
+   <country>sv</country>
+  </mobile_country>
+  <mobile_country mcc="708">
+   <country>hn</country>
+  </mobile_country>
+  <mobile_country mcc="710">
+   <country>ni</country>
+  </mobile_country>
+  <mobile_country mcc="712">
+   <country>cr</country>
+  </mobile_country>
+  <mobile_country mcc="714">
+   <country>pa</country>
+  </mobile_country>
+  <mobile_country mcc="716">
+   <country>pe</country>
+  </mobile_country>
+  <mobile_country mcc="722">
+   <country>ar</country>
+  </mobile_country>
+  <mobile_country mcc="724">
+   <country>br</country>
+  </mobile_country>
+  <mobile_country mcc="730">
+   <country>cl</country>
+  </mobile_country>
+  <mobile_country mcc="732">
+   <country>co</country>
+  </mobile_country>
+  <mobile_country mcc="734">
+   <country>ve</country>
+  </mobile_country>
+  <mobile_country mcc="736">
+   <country>bo</country>
+  </mobile_country>
+  <mobile_country mcc="738">
+   <country>gy</country>
+  </mobile_country>
+  <mobile_country mcc="740">
+   <country>ec</country>
+  </mobile_country>
+  <mobile_country mcc="742">
+   <country>gf</country>
+  </mobile_country>
+  <mobile_country mcc="744">
+   <country>py</country>
+  </mobile_country>
+  <mobile_country mcc="746">
+   <country>sr</country>
+  </mobile_country>
+  <mobile_country mcc="748">
+   <country>uy</country>
+  </mobile_country>
+  <mobile_country mcc="750">
+   <country>fk</country>
+  </mobile_country>
+ </mobile_countries>
 </telephony_lookup>
diff --git a/testing/data/test1/output_data/android/telephonylookup.xml b/testing/data/test1/output_data/android/telephonylookup.xml
index 17a7e9c..6582955 100644
--- a/testing/data/test1/output_data/android/telephonylookup.xml
+++ b/testing/data/test1/output_data/android/telephonylookup.xml
@@ -8,4 +8,732 @@
   <network mcc="310" mnc="470" country="gu"/>
   <network mcc="311" mnc="780" country="as"/>
  </networks>
+ <mobile_countries>
+  <mobile_country mcc="202">
+   <country>gr</country>
+  </mobile_country>
+  <mobile_country mcc="204">
+   <country>nl</country>
+  </mobile_country>
+  <mobile_country mcc="206">
+   <country>be</country>
+  </mobile_country>
+  <mobile_country mcc="208">
+   <country>fr</country>
+  </mobile_country>
+  <mobile_country mcc="212">
+   <country>mc</country>
+  </mobile_country>
+  <mobile_country mcc="213">
+   <country>ad</country>
+  </mobile_country>
+  <mobile_country mcc="214">
+   <country>es</country>
+  </mobile_country>
+  <mobile_country mcc="216">
+   <country>hu</country>
+  </mobile_country>
+  <mobile_country mcc="218">
+   <country>ba</country>
+  </mobile_country>
+  <mobile_country mcc="219">
+   <country>hr</country>
+  </mobile_country>
+  <mobile_country mcc="220">
+   <country>rs</country>
+  </mobile_country>
+  <mobile_country mcc="221">
+   <country>xk</country>
+  </mobile_country>
+  <mobile_country mcc="222">
+   <country>it</country>
+  </mobile_country>
+  <mobile_country mcc="225">
+   <country>va</country>
+  </mobile_country>
+  <mobile_country mcc="226">
+   <country>ro</country>
+  </mobile_country>
+  <mobile_country mcc="228">
+   <country>ch</country>
+  </mobile_country>
+  <mobile_country mcc="230">
+   <country>cz</country>
+  </mobile_country>
+  <mobile_country mcc="231">
+   <country>sk</country>
+  </mobile_country>
+  <mobile_country mcc="232">
+   <country>at</country>
+  </mobile_country>
+  <mobile_country mcc="234">
+   <country>gb</country>
+  </mobile_country>
+  <mobile_country mcc="235">
+   <country>gb</country>
+  </mobile_country>
+  <mobile_country mcc="238">
+   <country>dk</country>
+  </mobile_country>
+  <mobile_country mcc="240">
+   <country>se</country>
+  </mobile_country>
+  <mobile_country mcc="242">
+   <country>no</country>
+  </mobile_country>
+  <mobile_country mcc="244">
+   <country>fi</country>
+  </mobile_country>
+  <mobile_country mcc="246">
+   <country>lt</country>
+  </mobile_country>
+  <mobile_country mcc="247">
+   <country>lv</country>
+  </mobile_country>
+  <mobile_country mcc="248">
+   <country>ee</country>
+  </mobile_country>
+  <mobile_country mcc="250">
+   <country>ru</country>
+  </mobile_country>
+  <mobile_country mcc="255">
+   <country>ua</country>
+  </mobile_country>
+  <mobile_country mcc="257">
+   <country>by</country>
+  </mobile_country>
+  <mobile_country mcc="259">
+   <country>md</country>
+  </mobile_country>
+  <mobile_country mcc="260">
+   <country>pl</country>
+  </mobile_country>
+  <mobile_country mcc="262">
+   <country>de</country>
+  </mobile_country>
+  <mobile_country mcc="266">
+   <country>gi</country>
+  </mobile_country>
+  <mobile_country mcc="268">
+   <country>pt</country>
+  </mobile_country>
+  <mobile_country mcc="270">
+   <country>lu</country>
+  </mobile_country>
+  <mobile_country mcc="272">
+   <country>ie</country>
+  </mobile_country>
+  <mobile_country mcc="274">
+   <country>is</country>
+  </mobile_country>
+  <mobile_country mcc="276">
+   <country>al</country>
+  </mobile_country>
+  <mobile_country mcc="278">
+   <country>mt</country>
+  </mobile_country>
+  <mobile_country mcc="280">
+   <country>cy</country>
+  </mobile_country>
+  <mobile_country mcc="282">
+   <country>ge</country>
+  </mobile_country>
+  <mobile_country mcc="283">
+   <country>am</country>
+  </mobile_country>
+  <mobile_country mcc="284">
+   <country>bg</country>
+  </mobile_country>
+  <mobile_country mcc="286">
+   <country>tr</country>
+  </mobile_country>
+  <mobile_country mcc="288">
+   <country>fo</country>
+  </mobile_country>
+  <mobile_country mcc="289">
+   <country>ge</country>
+  </mobile_country>
+  <mobile_country mcc="290">
+   <country>gl</country>
+  </mobile_country>
+  <mobile_country mcc="292">
+   <country>sm</country>
+  </mobile_country>
+  <mobile_country mcc="293">
+   <country>si</country>
+  </mobile_country>
+  <mobile_country mcc="294">
+   <country>mk</country>
+  </mobile_country>
+  <mobile_country mcc="295">
+   <country>li</country>
+  </mobile_country>
+  <mobile_country mcc="297">
+   <country>me</country>
+  </mobile_country>
+  <mobile_country mcc="302">
+   <country>ca</country>
+  </mobile_country>
+  <mobile_country mcc="308">
+   <country>pm</country>
+  </mobile_country>
+  <mobile_country mcc="310">
+   <country>us</country>
+  </mobile_country>
+  <mobile_country mcc="311">
+   <country>us</country>
+  </mobile_country>
+  <mobile_country mcc="312">
+   <country>us</country>
+  </mobile_country>
+  <mobile_country mcc="313">
+   <country>us</country>
+  </mobile_country>
+  <mobile_country mcc="314">
+   <country>us</country>
+  </mobile_country>
+  <mobile_country mcc="315">
+   <country>us</country>
+  </mobile_country>
+  <mobile_country mcc="316">
+   <country>us</country>
+  </mobile_country>
+  <mobile_country mcc="330">
+   <country>pr</country>
+  </mobile_country>
+  <mobile_country mcc="332">
+   <country>vi</country>
+  </mobile_country>
+  <mobile_country mcc="334">
+   <country>mx</country>
+  </mobile_country>
+  <mobile_country mcc="338">
+   <country>jm</country>
+  </mobile_country>
+  <mobile_country mcc="340" default="gp">
+   <country>gp</country>
+   <country>gf</country>
+  </mobile_country>
+  <mobile_country mcc="342">
+   <country>bb</country>
+  </mobile_country>
+  <mobile_country mcc="344">
+   <country>ag</country>
+  </mobile_country>
+  <mobile_country mcc="346">
+   <country>ky</country>
+  </mobile_country>
+  <mobile_country mcc="348">
+   <country>vg</country>
+  </mobile_country>
+  <mobile_country mcc="350">
+   <country>bm</country>
+  </mobile_country>
+  <mobile_country mcc="352">
+   <country>gd</country>
+  </mobile_country>
+  <mobile_country mcc="354">
+   <country>ms</country>
+  </mobile_country>
+  <mobile_country mcc="356">
+   <country>kn</country>
+  </mobile_country>
+  <mobile_country mcc="358">
+   <country>lc</country>
+  </mobile_country>
+  <mobile_country mcc="360">
+   <country>vc</country>
+  </mobile_country>
+  <mobile_country mcc="362">
+   <country>cw</country>
+  </mobile_country>
+  <mobile_country mcc="363">
+   <country>aw</country>
+  </mobile_country>
+  <mobile_country mcc="364">
+   <country>bs</country>
+  </mobile_country>
+  <mobile_country mcc="365">
+   <country>ai</country>
+  </mobile_country>
+  <mobile_country mcc="366">
+   <country>dm</country>
+  </mobile_country>
+  <mobile_country mcc="368">
+   <country>cu</country>
+  </mobile_country>
+  <mobile_country mcc="370">
+   <country>do</country>
+  </mobile_country>
+  <mobile_country mcc="372">
+   <country>ht</country>
+  </mobile_country>
+  <mobile_country mcc="374">
+   <country>tt</country>
+  </mobile_country>
+  <mobile_country mcc="376">
+   <country>tc</country>
+  </mobile_country>
+  <mobile_country mcc="400">
+   <country>az</country>
+  </mobile_country>
+  <mobile_country mcc="401">
+   <country>kz</country>
+  </mobile_country>
+  <mobile_country mcc="402">
+   <country>bt</country>
+  </mobile_country>
+  <mobile_country mcc="404">
+   <country>in</country>
+  </mobile_country>
+  <mobile_country mcc="405">
+   <country>in</country>
+  </mobile_country>
+  <mobile_country mcc="406">
+   <country>in</country>
+  </mobile_country>
+  <mobile_country mcc="410">
+   <country>pk</country>
+  </mobile_country>
+  <mobile_country mcc="412">
+   <country>af</country>
+  </mobile_country>
+  <mobile_country mcc="413">
+   <country>lk</country>
+  </mobile_country>
+  <mobile_country mcc="414">
+   <country>mm</country>
+  </mobile_country>
+  <mobile_country mcc="415">
+   <country>lb</country>
+  </mobile_country>
+  <mobile_country mcc="416">
+   <country>jo</country>
+  </mobile_country>
+  <mobile_country mcc="417">
+   <country>sy</country>
+  </mobile_country>
+  <mobile_country mcc="418">
+   <country>iq</country>
+  </mobile_country>
+  <mobile_country mcc="419">
+   <country>kw</country>
+  </mobile_country>
+  <mobile_country mcc="420">
+   <country>sa</country>
+  </mobile_country>
+  <mobile_country mcc="421">
+   <country>ye</country>
+  </mobile_country>
+  <mobile_country mcc="422">
+   <country>om</country>
+  </mobile_country>
+  <mobile_country mcc="423">
+   <country>ps</country>
+  </mobile_country>
+  <mobile_country mcc="424">
+   <country>ae</country>
+  </mobile_country>
+  <mobile_country mcc="425">
+   <country>il</country>
+  </mobile_country>
+  <mobile_country mcc="426">
+   <country>bh</country>
+  </mobile_country>
+  <mobile_country mcc="427">
+   <country>qa</country>
+  </mobile_country>
+  <mobile_country mcc="428">
+   <country>mn</country>
+  </mobile_country>
+  <mobile_country mcc="429">
+   <country>np</country>
+  </mobile_country>
+  <mobile_country mcc="430">
+   <country>ae</country>
+  </mobile_country>
+  <mobile_country mcc="431">
+   <country>ae</country>
+  </mobile_country>
+  <mobile_country mcc="432">
+   <country>ir</country>
+  </mobile_country>
+  <mobile_country mcc="434">
+   <country>uz</country>
+  </mobile_country>
+  <mobile_country mcc="436">
+   <country>tj</country>
+  </mobile_country>
+  <mobile_country mcc="437">
+   <country>kg</country>
+  </mobile_country>
+  <mobile_country mcc="438">
+   <country>tm</country>
+  </mobile_country>
+  <mobile_country mcc="440">
+   <country>jp</country>
+  </mobile_country>
+  <mobile_country mcc="441">
+   <country>jp</country>
+  </mobile_country>
+  <mobile_country mcc="450">
+   <country>kr</country>
+  </mobile_country>
+  <mobile_country mcc="452">
+   <country>vn</country>
+  </mobile_country>
+  <mobile_country mcc="454">
+   <country>hk</country>
+  </mobile_country>
+  <mobile_country mcc="455">
+   <country>mo</country>
+  </mobile_country>
+  <mobile_country mcc="456">
+   <country>kh</country>
+  </mobile_country>
+  <mobile_country mcc="457">
+   <country>la</country>
+  </mobile_country>
+  <mobile_country mcc="460">
+   <country>cn</country>
+  </mobile_country>
+  <mobile_country mcc="461">
+   <country>cn</country>
+  </mobile_country>
+  <mobile_country mcc="466">
+   <country>tw</country>
+  </mobile_country>
+  <mobile_country mcc="467">
+   <country>kp</country>
+  </mobile_country>
+  <mobile_country mcc="470">
+   <country>bd</country>
+  </mobile_country>
+  <mobile_country mcc="472">
+   <country>mv</country>
+  </mobile_country>
+  <mobile_country mcc="502">
+   <country>my</country>
+  </mobile_country>
+  <mobile_country mcc="505" default="au">
+   <country>au</country>
+   <country>nf</country>
+  </mobile_country>
+  <mobile_country mcc="510">
+   <country>id</country>
+  </mobile_country>
+  <mobile_country mcc="514">
+   <country>tl</country>
+  </mobile_country>
+  <mobile_country mcc="515">
+   <country>ph</country>
+  </mobile_country>
+  <mobile_country mcc="520">
+   <country>th</country>
+  </mobile_country>
+  <mobile_country mcc="525">
+   <country>sg</country>
+  </mobile_country>
+  <mobile_country mcc="528">
+   <country>bn</country>
+  </mobile_country>
+  <mobile_country mcc="530">
+   <country>nz</country>
+  </mobile_country>
+  <mobile_country mcc="534">
+   <country>mp</country>
+  </mobile_country>
+  <mobile_country mcc="535">
+   <country>gu</country>
+  </mobile_country>
+  <mobile_country mcc="536">
+   <country>nr</country>
+  </mobile_country>
+  <mobile_country mcc="537">
+   <country>pg</country>
+  </mobile_country>
+  <mobile_country mcc="539">
+   <country>to</country>
+  </mobile_country>
+  <mobile_country mcc="540">
+   <country>sb</country>
+  </mobile_country>
+  <mobile_country mcc="541">
+   <country>vu</country>
+  </mobile_country>
+  <mobile_country mcc="542">
+   <country>fj</country>
+  </mobile_country>
+  <mobile_country mcc="543">
+   <country>wf</country>
+  </mobile_country>
+  <mobile_country mcc="544">
+   <country>as</country>
+  </mobile_country>
+  <mobile_country mcc="545">
+   <country>ki</country>
+  </mobile_country>
+  <mobile_country mcc="546">
+   <country>nc</country>
+  </mobile_country>
+  <mobile_country mcc="547">
+   <country>pf</country>
+  </mobile_country>
+  <mobile_country mcc="548">
+   <country>ck</country>
+  </mobile_country>
+  <mobile_country mcc="549">
+   <country>ws</country>
+  </mobile_country>
+  <mobile_country mcc="550">
+   <country>fm</country>
+  </mobile_country>
+  <mobile_country mcc="551">
+   <country>mh</country>
+  </mobile_country>
+  <mobile_country mcc="552">
+   <country>pw</country>
+  </mobile_country>
+  <mobile_country mcc="553">
+   <country>tv</country>
+  </mobile_country>
+  <mobile_country mcc="554">
+   <country>tk</country>
+  </mobile_country>
+  <mobile_country mcc="555">
+   <country>nu</country>
+  </mobile_country>
+  <mobile_country mcc="602">
+   <country>eg</country>
+  </mobile_country>
+  <mobile_country mcc="603">
+   <country>dz</country>
+  </mobile_country>
+  <mobile_country mcc="604">
+   <country>ma</country>
+  </mobile_country>
+  <mobile_country mcc="605">
+   <country>tn</country>
+  </mobile_country>
+  <mobile_country mcc="606">
+   <country>ly</country>
+  </mobile_country>
+  <mobile_country mcc="607">
+   <country>gm</country>
+  </mobile_country>
+  <mobile_country mcc="608">
+   <country>sn</country>
+  </mobile_country>
+  <mobile_country mcc="609">
+   <country>mr</country>
+  </mobile_country>
+  <mobile_country mcc="610">
+   <country>ml</country>
+  </mobile_country>
+  <mobile_country mcc="611">
+   <country>gn</country>
+  </mobile_country>
+  <mobile_country mcc="612">
+   <country>ci</country>
+  </mobile_country>
+  <mobile_country mcc="613">
+   <country>bf</country>
+  </mobile_country>
+  <mobile_country mcc="614">
+   <country>ne</country>
+  </mobile_country>
+  <mobile_country mcc="615">
+   <country>tg</country>
+  </mobile_country>
+  <mobile_country mcc="616">
+   <country>bj</country>
+  </mobile_country>
+  <mobile_country mcc="617">
+   <country>mu</country>
+  </mobile_country>
+  <mobile_country mcc="618">
+   <country>lr</country>
+  </mobile_country>
+  <mobile_country mcc="619">
+   <country>sl</country>
+  </mobile_country>
+  <mobile_country mcc="620">
+   <country>gh</country>
+  </mobile_country>
+  <mobile_country mcc="621">
+   <country>ng</country>
+  </mobile_country>
+  <mobile_country mcc="622">
+   <country>td</country>
+  </mobile_country>
+  <mobile_country mcc="623">
+   <country>cf</country>
+  </mobile_country>
+  <mobile_country mcc="624">
+   <country>cm</country>
+  </mobile_country>
+  <mobile_country mcc="625">
+   <country>cv</country>
+  </mobile_country>
+  <mobile_country mcc="626">
+   <country>st</country>
+  </mobile_country>
+  <mobile_country mcc="627">
+   <country>gq</country>
+  </mobile_country>
+  <mobile_country mcc="628">
+   <country>ga</country>
+  </mobile_country>
+  <mobile_country mcc="629">
+   <country>cg</country>
+  </mobile_country>
+  <mobile_country mcc="630">
+   <country>cd</country>
+  </mobile_country>
+  <mobile_country mcc="631">
+   <country>ao</country>
+  </mobile_country>
+  <mobile_country mcc="632">
+   <country>gw</country>
+  </mobile_country>
+  <mobile_country mcc="633">
+   <country>sc</country>
+  </mobile_country>
+  <mobile_country mcc="634">
+   <country>sd</country>
+  </mobile_country>
+  <mobile_country mcc="635">
+   <country>rw</country>
+  </mobile_country>
+  <mobile_country mcc="636">
+   <country>et</country>
+  </mobile_country>
+  <mobile_country mcc="637">
+   <country>so</country>
+  </mobile_country>
+  <mobile_country mcc="638">
+   <country>dj</country>
+  </mobile_country>
+  <mobile_country mcc="639">
+   <country>ke</country>
+  </mobile_country>
+  <mobile_country mcc="640">
+   <country>tz</country>
+  </mobile_country>
+  <mobile_country mcc="641">
+   <country>ug</country>
+  </mobile_country>
+  <mobile_country mcc="642">
+   <country>bi</country>
+  </mobile_country>
+  <mobile_country mcc="643">
+   <country>mz</country>
+  </mobile_country>
+  <mobile_country mcc="645">
+   <country>zm</country>
+  </mobile_country>
+  <mobile_country mcc="646">
+   <country>mg</country>
+  </mobile_country>
+  <mobile_country mcc="647" default="re">
+   <country>re</country>
+   <country>yt</country>
+  </mobile_country>
+  <mobile_country mcc="648">
+   <country>zw</country>
+  </mobile_country>
+  <mobile_country mcc="649">
+   <country>na</country>
+  </mobile_country>
+  <mobile_country mcc="650">
+   <country>mw</country>
+  </mobile_country>
+  <mobile_country mcc="651">
+   <country>ls</country>
+  </mobile_country>
+  <mobile_country mcc="652">
+   <country>bw</country>
+  </mobile_country>
+  <mobile_country mcc="653">
+   <country>sz</country>
+  </mobile_country>
+  <mobile_country mcc="654">
+   <country>km</country>
+  </mobile_country>
+  <mobile_country mcc="655">
+   <country>za</country>
+  </mobile_country>
+  <mobile_country mcc="657">
+   <country>er</country>
+  </mobile_country>
+  <mobile_country mcc="658">
+   <country>sh</country>
+  </mobile_country>
+  <mobile_country mcc="659">
+   <country>ss</country>
+  </mobile_country>
+  <mobile_country mcc="702">
+   <country>bz</country>
+  </mobile_country>
+  <mobile_country mcc="704">
+   <country>gt</country>
+  </mobile_country>
+  <mobile_country mcc="706">
+   <country>sv</country>
+  </mobile_country>
+  <mobile_country mcc="708">
+   <country>hn</country>
+  </mobile_country>
+  <mobile_country mcc="710">
+   <country>ni</country>
+  </mobile_country>
+  <mobile_country mcc="712">
+   <country>cr</country>
+  </mobile_country>
+  <mobile_country mcc="714">
+   <country>pa</country>
+  </mobile_country>
+  <mobile_country mcc="716">
+   <country>pe</country>
+  </mobile_country>
+  <mobile_country mcc="722">
+   <country>ar</country>
+  </mobile_country>
+  <mobile_country mcc="724">
+   <country>br</country>
+  </mobile_country>
+  <mobile_country mcc="730">
+   <country>cl</country>
+  </mobile_country>
+  <mobile_country mcc="732">
+   <country>co</country>
+  </mobile_country>
+  <mobile_country mcc="734">
+   <country>ve</country>
+  </mobile_country>
+  <mobile_country mcc="736">
+   <country>bo</country>
+  </mobile_country>
+  <mobile_country mcc="738">
+   <country>gy</country>
+  </mobile_country>
+  <mobile_country mcc="740">
+   <country>ec</country>
+  </mobile_country>
+  <mobile_country mcc="742">
+   <country>gf</country>
+  </mobile_country>
+  <mobile_country mcc="744">
+   <country>py</country>
+  </mobile_country>
+  <mobile_country mcc="746">
+   <country>sr</country>
+  </mobile_country>
+  <mobile_country mcc="748">
+   <country>uy</country>
+  </mobile_country>
+  <mobile_country mcc="750">
+   <country>fk</country>
+  </mobile_country>
+ </mobile_countries>
 </telephony_lookup>
diff --git a/testing/data/test3/output_data/android/telephonylookup.xml b/testing/data/test3/output_data/android/telephonylookup.xml
index 17a7e9c..6582955 100644
--- a/testing/data/test3/output_data/android/telephonylookup.xml
+++ b/testing/data/test3/output_data/android/telephonylookup.xml
@@ -8,4 +8,732 @@
   <network mcc="310" mnc="470" country="gu"/>
   <network mcc="311" mnc="780" country="as"/>
  </networks>
+ <mobile_countries>
+  <mobile_country mcc="202">
+   <country>gr</country>
+  </mobile_country>
+  <mobile_country mcc="204">
+   <country>nl</country>
+  </mobile_country>
+  <mobile_country mcc="206">
+   <country>be</country>
+  </mobile_country>
+  <mobile_country mcc="208">
+   <country>fr</country>
+  </mobile_country>
+  <mobile_country mcc="212">
+   <country>mc</country>
+  </mobile_country>
+  <mobile_country mcc="213">
+   <country>ad</country>
+  </mobile_country>
+  <mobile_country mcc="214">
+   <country>es</country>
+  </mobile_country>
+  <mobile_country mcc="216">
+   <country>hu</country>
+  </mobile_country>
+  <mobile_country mcc="218">
+   <country>ba</country>
+  </mobile_country>
+  <mobile_country mcc="219">
+   <country>hr</country>
+  </mobile_country>
+  <mobile_country mcc="220">
+   <country>rs</country>
+  </mobile_country>
+  <mobile_country mcc="221">
+   <country>xk</country>
+  </mobile_country>
+  <mobile_country mcc="222">
+   <country>it</country>
+  </mobile_country>
+  <mobile_country mcc="225">
+   <country>va</country>
+  </mobile_country>
+  <mobile_country mcc="226">
+   <country>ro</country>
+  </mobile_country>
+  <mobile_country mcc="228">
+   <country>ch</country>
+  </mobile_country>
+  <mobile_country mcc="230">
+   <country>cz</country>
+  </mobile_country>
+  <mobile_country mcc="231">
+   <country>sk</country>
+  </mobile_country>
+  <mobile_country mcc="232">
+   <country>at</country>
+  </mobile_country>
+  <mobile_country mcc="234">
+   <country>gb</country>
+  </mobile_country>
+  <mobile_country mcc="235">
+   <country>gb</country>
+  </mobile_country>
+  <mobile_country mcc="238">
+   <country>dk</country>
+  </mobile_country>
+  <mobile_country mcc="240">
+   <country>se</country>
+  </mobile_country>
+  <mobile_country mcc="242">
+   <country>no</country>
+  </mobile_country>
+  <mobile_country mcc="244">
+   <country>fi</country>
+  </mobile_country>
+  <mobile_country mcc="246">
+   <country>lt</country>
+  </mobile_country>
+  <mobile_country mcc="247">
+   <country>lv</country>
+  </mobile_country>
+  <mobile_country mcc="248">
+   <country>ee</country>
+  </mobile_country>
+  <mobile_country mcc="250">
+   <country>ru</country>
+  </mobile_country>
+  <mobile_country mcc="255">
+   <country>ua</country>
+  </mobile_country>
+  <mobile_country mcc="257">
+   <country>by</country>
+  </mobile_country>
+  <mobile_country mcc="259">
+   <country>md</country>
+  </mobile_country>
+  <mobile_country mcc="260">
+   <country>pl</country>
+  </mobile_country>
+  <mobile_country mcc="262">
+   <country>de</country>
+  </mobile_country>
+  <mobile_country mcc="266">
+   <country>gi</country>
+  </mobile_country>
+  <mobile_country mcc="268">
+   <country>pt</country>
+  </mobile_country>
+  <mobile_country mcc="270">
+   <country>lu</country>
+  </mobile_country>
+  <mobile_country mcc="272">
+   <country>ie</country>
+  </mobile_country>
+  <mobile_country mcc="274">
+   <country>is</country>
+  </mobile_country>
+  <mobile_country mcc="276">
+   <country>al</country>
+  </mobile_country>
+  <mobile_country mcc="278">
+   <country>mt</country>
+  </mobile_country>
+  <mobile_country mcc="280">
+   <country>cy</country>
+  </mobile_country>
+  <mobile_country mcc="282">
+   <country>ge</country>
+  </mobile_country>
+  <mobile_country mcc="283">
+   <country>am</country>
+  </mobile_country>
+  <mobile_country mcc="284">
+   <country>bg</country>
+  </mobile_country>
+  <mobile_country mcc="286">
+   <country>tr</country>
+  </mobile_country>
+  <mobile_country mcc="288">
+   <country>fo</country>
+  </mobile_country>
+  <mobile_country mcc="289">
+   <country>ge</country>
+  </mobile_country>
+  <mobile_country mcc="290">
+   <country>gl</country>
+  </mobile_country>
+  <mobile_country mcc="292">
+   <country>sm</country>
+  </mobile_country>
+  <mobile_country mcc="293">
+   <country>si</country>
+  </mobile_country>
+  <mobile_country mcc="294">
+   <country>mk</country>
+  </mobile_country>
+  <mobile_country mcc="295">
+   <country>li</country>
+  </mobile_country>
+  <mobile_country mcc="297">
+   <country>me</country>
+  </mobile_country>
+  <mobile_country mcc="302">
+   <country>ca</country>
+  </mobile_country>
+  <mobile_country mcc="308">
+   <country>pm</country>
+  </mobile_country>
+  <mobile_country mcc="310">
+   <country>us</country>
+  </mobile_country>
+  <mobile_country mcc="311">
+   <country>us</country>
+  </mobile_country>
+  <mobile_country mcc="312">
+   <country>us</country>
+  </mobile_country>
+  <mobile_country mcc="313">
+   <country>us</country>
+  </mobile_country>
+  <mobile_country mcc="314">
+   <country>us</country>
+  </mobile_country>
+  <mobile_country mcc="315">
+   <country>us</country>
+  </mobile_country>
+  <mobile_country mcc="316">
+   <country>us</country>
+  </mobile_country>
+  <mobile_country mcc="330">
+   <country>pr</country>
+  </mobile_country>
+  <mobile_country mcc="332">
+   <country>vi</country>
+  </mobile_country>
+  <mobile_country mcc="334">
+   <country>mx</country>
+  </mobile_country>
+  <mobile_country mcc="338">
+   <country>jm</country>
+  </mobile_country>
+  <mobile_country mcc="340" default="gp">
+   <country>gp</country>
+   <country>gf</country>
+  </mobile_country>
+  <mobile_country mcc="342">
+   <country>bb</country>
+  </mobile_country>
+  <mobile_country mcc="344">
+   <country>ag</country>
+  </mobile_country>
+  <mobile_country mcc="346">
+   <country>ky</country>
+  </mobile_country>
+  <mobile_country mcc="348">
+   <country>vg</country>
+  </mobile_country>
+  <mobile_country mcc="350">
+   <country>bm</country>
+  </mobile_country>
+  <mobile_country mcc="352">
+   <country>gd</country>
+  </mobile_country>
+  <mobile_country mcc="354">
+   <country>ms</country>
+  </mobile_country>
+  <mobile_country mcc="356">
+   <country>kn</country>
+  </mobile_country>
+  <mobile_country mcc="358">
+   <country>lc</country>
+  </mobile_country>
+  <mobile_country mcc="360">
+   <country>vc</country>
+  </mobile_country>
+  <mobile_country mcc="362">
+   <country>cw</country>
+  </mobile_country>
+  <mobile_country mcc="363">
+   <country>aw</country>
+  </mobile_country>
+  <mobile_country mcc="364">
+   <country>bs</country>
+  </mobile_country>
+  <mobile_country mcc="365">
+   <country>ai</country>
+  </mobile_country>
+  <mobile_country mcc="366">
+   <country>dm</country>
+  </mobile_country>
+  <mobile_country mcc="368">
+   <country>cu</country>
+  </mobile_country>
+  <mobile_country mcc="370">
+   <country>do</country>
+  </mobile_country>
+  <mobile_country mcc="372">
+   <country>ht</country>
+  </mobile_country>
+  <mobile_country mcc="374">
+   <country>tt</country>
+  </mobile_country>
+  <mobile_country mcc="376">
+   <country>tc</country>
+  </mobile_country>
+  <mobile_country mcc="400">
+   <country>az</country>
+  </mobile_country>
+  <mobile_country mcc="401">
+   <country>kz</country>
+  </mobile_country>
+  <mobile_country mcc="402">
+   <country>bt</country>
+  </mobile_country>
+  <mobile_country mcc="404">
+   <country>in</country>
+  </mobile_country>
+  <mobile_country mcc="405">
+   <country>in</country>
+  </mobile_country>
+  <mobile_country mcc="406">
+   <country>in</country>
+  </mobile_country>
+  <mobile_country mcc="410">
+   <country>pk</country>
+  </mobile_country>
+  <mobile_country mcc="412">
+   <country>af</country>
+  </mobile_country>
+  <mobile_country mcc="413">
+   <country>lk</country>
+  </mobile_country>
+  <mobile_country mcc="414">
+   <country>mm</country>
+  </mobile_country>
+  <mobile_country mcc="415">
+   <country>lb</country>
+  </mobile_country>
+  <mobile_country mcc="416">
+   <country>jo</country>
+  </mobile_country>
+  <mobile_country mcc="417">
+   <country>sy</country>
+  </mobile_country>
+  <mobile_country mcc="418">
+   <country>iq</country>
+  </mobile_country>
+  <mobile_country mcc="419">
+   <country>kw</country>
+  </mobile_country>
+  <mobile_country mcc="420">
+   <country>sa</country>
+  </mobile_country>
+  <mobile_country mcc="421">
+   <country>ye</country>
+  </mobile_country>
+  <mobile_country mcc="422">
+   <country>om</country>
+  </mobile_country>
+  <mobile_country mcc="423">
+   <country>ps</country>
+  </mobile_country>
+  <mobile_country mcc="424">
+   <country>ae</country>
+  </mobile_country>
+  <mobile_country mcc="425">
+   <country>il</country>
+  </mobile_country>
+  <mobile_country mcc="426">
+   <country>bh</country>
+  </mobile_country>
+  <mobile_country mcc="427">
+   <country>qa</country>
+  </mobile_country>
+  <mobile_country mcc="428">
+   <country>mn</country>
+  </mobile_country>
+  <mobile_country mcc="429">
+   <country>np</country>
+  </mobile_country>
+  <mobile_country mcc="430">
+   <country>ae</country>
+  </mobile_country>
+  <mobile_country mcc="431">
+   <country>ae</country>
+  </mobile_country>
+  <mobile_country mcc="432">
+   <country>ir</country>
+  </mobile_country>
+  <mobile_country mcc="434">
+   <country>uz</country>
+  </mobile_country>
+  <mobile_country mcc="436">
+   <country>tj</country>
+  </mobile_country>
+  <mobile_country mcc="437">
+   <country>kg</country>
+  </mobile_country>
+  <mobile_country mcc="438">
+   <country>tm</country>
+  </mobile_country>
+  <mobile_country mcc="440">
+   <country>jp</country>
+  </mobile_country>
+  <mobile_country mcc="441">
+   <country>jp</country>
+  </mobile_country>
+  <mobile_country mcc="450">
+   <country>kr</country>
+  </mobile_country>
+  <mobile_country mcc="452">
+   <country>vn</country>
+  </mobile_country>
+  <mobile_country mcc="454">
+   <country>hk</country>
+  </mobile_country>
+  <mobile_country mcc="455">
+   <country>mo</country>
+  </mobile_country>
+  <mobile_country mcc="456">
+   <country>kh</country>
+  </mobile_country>
+  <mobile_country mcc="457">
+   <country>la</country>
+  </mobile_country>
+  <mobile_country mcc="460">
+   <country>cn</country>
+  </mobile_country>
+  <mobile_country mcc="461">
+   <country>cn</country>
+  </mobile_country>
+  <mobile_country mcc="466">
+   <country>tw</country>
+  </mobile_country>
+  <mobile_country mcc="467">
+   <country>kp</country>
+  </mobile_country>
+  <mobile_country mcc="470">
+   <country>bd</country>
+  </mobile_country>
+  <mobile_country mcc="472">
+   <country>mv</country>
+  </mobile_country>
+  <mobile_country mcc="502">
+   <country>my</country>
+  </mobile_country>
+  <mobile_country mcc="505" default="au">
+   <country>au</country>
+   <country>nf</country>
+  </mobile_country>
+  <mobile_country mcc="510">
+   <country>id</country>
+  </mobile_country>
+  <mobile_country mcc="514">
+   <country>tl</country>
+  </mobile_country>
+  <mobile_country mcc="515">
+   <country>ph</country>
+  </mobile_country>
+  <mobile_country mcc="520">
+   <country>th</country>
+  </mobile_country>
+  <mobile_country mcc="525">
+   <country>sg</country>
+  </mobile_country>
+  <mobile_country mcc="528">
+   <country>bn</country>
+  </mobile_country>
+  <mobile_country mcc="530">
+   <country>nz</country>
+  </mobile_country>
+  <mobile_country mcc="534">
+   <country>mp</country>
+  </mobile_country>
+  <mobile_country mcc="535">
+   <country>gu</country>
+  </mobile_country>
+  <mobile_country mcc="536">
+   <country>nr</country>
+  </mobile_country>
+  <mobile_country mcc="537">
+   <country>pg</country>
+  </mobile_country>
+  <mobile_country mcc="539">
+   <country>to</country>
+  </mobile_country>
+  <mobile_country mcc="540">
+   <country>sb</country>
+  </mobile_country>
+  <mobile_country mcc="541">
+   <country>vu</country>
+  </mobile_country>
+  <mobile_country mcc="542">
+   <country>fj</country>
+  </mobile_country>
+  <mobile_country mcc="543">
+   <country>wf</country>
+  </mobile_country>
+  <mobile_country mcc="544">
+   <country>as</country>
+  </mobile_country>
+  <mobile_country mcc="545">
+   <country>ki</country>
+  </mobile_country>
+  <mobile_country mcc="546">
+   <country>nc</country>
+  </mobile_country>
+  <mobile_country mcc="547">
+   <country>pf</country>
+  </mobile_country>
+  <mobile_country mcc="548">
+   <country>ck</country>
+  </mobile_country>
+  <mobile_country mcc="549">
+   <country>ws</country>
+  </mobile_country>
+  <mobile_country mcc="550">
+   <country>fm</country>
+  </mobile_country>
+  <mobile_country mcc="551">
+   <country>mh</country>
+  </mobile_country>
+  <mobile_country mcc="552">
+   <country>pw</country>
+  </mobile_country>
+  <mobile_country mcc="553">
+   <country>tv</country>
+  </mobile_country>
+  <mobile_country mcc="554">
+   <country>tk</country>
+  </mobile_country>
+  <mobile_country mcc="555">
+   <country>nu</country>
+  </mobile_country>
+  <mobile_country mcc="602">
+   <country>eg</country>
+  </mobile_country>
+  <mobile_country mcc="603">
+   <country>dz</country>
+  </mobile_country>
+  <mobile_country mcc="604">
+   <country>ma</country>
+  </mobile_country>
+  <mobile_country mcc="605">
+   <country>tn</country>
+  </mobile_country>
+  <mobile_country mcc="606">
+   <country>ly</country>
+  </mobile_country>
+  <mobile_country mcc="607">
+   <country>gm</country>
+  </mobile_country>
+  <mobile_country mcc="608">
+   <country>sn</country>
+  </mobile_country>
+  <mobile_country mcc="609">
+   <country>mr</country>
+  </mobile_country>
+  <mobile_country mcc="610">
+   <country>ml</country>
+  </mobile_country>
+  <mobile_country mcc="611">
+   <country>gn</country>
+  </mobile_country>
+  <mobile_country mcc="612">
+   <country>ci</country>
+  </mobile_country>
+  <mobile_country mcc="613">
+   <country>bf</country>
+  </mobile_country>
+  <mobile_country mcc="614">
+   <country>ne</country>
+  </mobile_country>
+  <mobile_country mcc="615">
+   <country>tg</country>
+  </mobile_country>
+  <mobile_country mcc="616">
+   <country>bj</country>
+  </mobile_country>
+  <mobile_country mcc="617">
+   <country>mu</country>
+  </mobile_country>
+  <mobile_country mcc="618">
+   <country>lr</country>
+  </mobile_country>
+  <mobile_country mcc="619">
+   <country>sl</country>
+  </mobile_country>
+  <mobile_country mcc="620">
+   <country>gh</country>
+  </mobile_country>
+  <mobile_country mcc="621">
+   <country>ng</country>
+  </mobile_country>
+  <mobile_country mcc="622">
+   <country>td</country>
+  </mobile_country>
+  <mobile_country mcc="623">
+   <country>cf</country>
+  </mobile_country>
+  <mobile_country mcc="624">
+   <country>cm</country>
+  </mobile_country>
+  <mobile_country mcc="625">
+   <country>cv</country>
+  </mobile_country>
+  <mobile_country mcc="626">
+   <country>st</country>
+  </mobile_country>
+  <mobile_country mcc="627">
+   <country>gq</country>
+  </mobile_country>
+  <mobile_country mcc="628">
+   <country>ga</country>
+  </mobile_country>
+  <mobile_country mcc="629">
+   <country>cg</country>
+  </mobile_country>
+  <mobile_country mcc="630">
+   <country>cd</country>
+  </mobile_country>
+  <mobile_country mcc="631">
+   <country>ao</country>
+  </mobile_country>
+  <mobile_country mcc="632">
+   <country>gw</country>
+  </mobile_country>
+  <mobile_country mcc="633">
+   <country>sc</country>
+  </mobile_country>
+  <mobile_country mcc="634">
+   <country>sd</country>
+  </mobile_country>
+  <mobile_country mcc="635">
+   <country>rw</country>
+  </mobile_country>
+  <mobile_country mcc="636">
+   <country>et</country>
+  </mobile_country>
+  <mobile_country mcc="637">
+   <country>so</country>
+  </mobile_country>
+  <mobile_country mcc="638">
+   <country>dj</country>
+  </mobile_country>
+  <mobile_country mcc="639">
+   <country>ke</country>
+  </mobile_country>
+  <mobile_country mcc="640">
+   <country>tz</country>
+  </mobile_country>
+  <mobile_country mcc="641">
+   <country>ug</country>
+  </mobile_country>
+  <mobile_country mcc="642">
+   <country>bi</country>
+  </mobile_country>
+  <mobile_country mcc="643">
+   <country>mz</country>
+  </mobile_country>
+  <mobile_country mcc="645">
+   <country>zm</country>
+  </mobile_country>
+  <mobile_country mcc="646">
+   <country>mg</country>
+  </mobile_country>
+  <mobile_country mcc="647" default="re">
+   <country>re</country>
+   <country>yt</country>
+  </mobile_country>
+  <mobile_country mcc="648">
+   <country>zw</country>
+  </mobile_country>
+  <mobile_country mcc="649">
+   <country>na</country>
+  </mobile_country>
+  <mobile_country mcc="650">
+   <country>mw</country>
+  </mobile_country>
+  <mobile_country mcc="651">
+   <country>ls</country>
+  </mobile_country>
+  <mobile_country mcc="652">
+   <country>bw</country>
+  </mobile_country>
+  <mobile_country mcc="653">
+   <country>sz</country>
+  </mobile_country>
+  <mobile_country mcc="654">
+   <country>km</country>
+  </mobile_country>
+  <mobile_country mcc="655">
+   <country>za</country>
+  </mobile_country>
+  <mobile_country mcc="657">
+   <country>er</country>
+  </mobile_country>
+  <mobile_country mcc="658">
+   <country>sh</country>
+  </mobile_country>
+  <mobile_country mcc="659">
+   <country>ss</country>
+  </mobile_country>
+  <mobile_country mcc="702">
+   <country>bz</country>
+  </mobile_country>
+  <mobile_country mcc="704">
+   <country>gt</country>
+  </mobile_country>
+  <mobile_country mcc="706">
+   <country>sv</country>
+  </mobile_country>
+  <mobile_country mcc="708">
+   <country>hn</country>
+  </mobile_country>
+  <mobile_country mcc="710">
+   <country>ni</country>
+  </mobile_country>
+  <mobile_country mcc="712">
+   <country>cr</country>
+  </mobile_country>
+  <mobile_country mcc="714">
+   <country>pa</country>
+  </mobile_country>
+  <mobile_country mcc="716">
+   <country>pe</country>
+  </mobile_country>
+  <mobile_country mcc="722">
+   <country>ar</country>
+  </mobile_country>
+  <mobile_country mcc="724">
+   <country>br</country>
+  </mobile_country>
+  <mobile_country mcc="730">
+   <country>cl</country>
+  </mobile_country>
+  <mobile_country mcc="732">
+   <country>co</country>
+  </mobile_country>
+  <mobile_country mcc="734">
+   <country>ve</country>
+  </mobile_country>
+  <mobile_country mcc="736">
+   <country>bo</country>
+  </mobile_country>
+  <mobile_country mcc="738">
+   <country>gy</country>
+  </mobile_country>
+  <mobile_country mcc="740">
+   <country>ec</country>
+  </mobile_country>
+  <mobile_country mcc="742">
+   <country>gf</country>
+  </mobile_country>
+  <mobile_country mcc="744">
+   <country>py</country>
+  </mobile_country>
+  <mobile_country mcc="746">
+   <country>sr</country>
+  </mobile_country>
+  <mobile_country mcc="748">
+   <country>uy</country>
+  </mobile_country>
+  <mobile_country mcc="750">
+   <country>fk</country>
+  </mobile_country>
+ </mobile_countries>
 </telephony_lookup>
```

