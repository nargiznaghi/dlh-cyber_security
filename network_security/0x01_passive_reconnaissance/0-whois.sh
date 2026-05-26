#!/bin/bash

domain="$1"
whois "$domain" | awk -F': ' '
/Registrant Name/          {print "Registrant Name," $2}
/Registrant Organization/   {print "Registrant Organization," $2}
/Registrant Street/         {print "Registrant Street," $2 " "}
/Registrant City/           {print "Registrant City," $2}
/Registrant State/          {print "Registrant State/Province," $2}
/Registrant Postal Code/    {print "Registrant Postal Code," $2}
/Registrant Country/        {print "Registrant Country," $2}
/Registrant Phone$/         {print "Registrant Phone," $2}
/Registrant Phone Ext/      {print "Registrant Phone Ext:,"}
/Registrant Fax$/           {print "Registrant Fax," $2}
/Registrant Fax Ext/        {print "Registrant Fax Ext:,"}
/Registrant Email/          {print "Registrant Email," $2}

/Admin Name/                {print "Admin Name," $2}
/Admin Organization/        {print "Admin Organization," $2}
/Admin Street/              {print "Admin Street," $2 " "}
/Admin City/                {print "Admin City," $2}
/Admin State/               {print "Admin State/Province," $2}
/Admin Postal Code/         {print "Admin Postal Code," $2}
/Admin Country/             {print "Admin Country," $2}
/Admin Phone$/              {print "Admin Phone," $2}
/Admin Phone Ext/           {print "Admin Phone Ext:,"}
/Admin Fax$/                {print "Admin Fax," $2}
/Admin Fax Ext/             {print "Admin Fax Ext:,"}
/Admin Email/               {print "Admin Email," $2}

/Tech Name/                 {print "Tech Name," $2}
/Tech Organization/         {print "Tech Organization," $2}
/Tech Street/               {print "Tech Street," $2 " "}
/Tech City/                 {print "Tech City," $2}
/Tech State/                {print "Tech State/Province," $2}
/Tech Postal Code/          {print "Tech Postal Code," $2}
/Tech Country/              {print "Tech Country," $2}
/Tech Phone$/               {print "Tech Phone," $2}
/Tech Phone Ext/            {print "Tech Phone Ext:,"}
/Tech Fax$/                 {print "Tech Fax," $2}
/Tech Fax Ext/              {print "Tech Fax Ext:,"}
/Tech Email/                {print "Tech Email," $2}
' > "$domain.csv"
