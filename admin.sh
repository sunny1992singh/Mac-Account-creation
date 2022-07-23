# Add User OSX Command Line
# =========================

# An easy add user script for Max OSX.
# Although I wrote this for 10.7 Lion Server, these commands have been the same since 10.5 Leopard.
# It's pretty simple as it uses and strings together the (rustic and ancient) commands that OSX 
# already uses to add users.

# === Typically, this is all the info you need to enter ===

echo "Enter your desired user name: "
read USERNAME

echo "Enter a full name for this user: "
read FULLNAME

echo "Enter a password for this user: "
read -s PASSWORD

# ====

# A list of (secondary) groups the user should belong to
# This makes the difference between admin and non-admin users.

echo "Is this an administrative user? (y/n)"
read GROUP_ADD

if [ "$GROUP_ADD" = n ] ; then
    SECONDARY_GROUPS="staff"  # for a non-admin user
elif [ "$GROUP_ADD" = y ] ; then
    SECONDARY_GROUPS="admin _lpadmin _appserveradm _appserverusr" # for an admin user
else
    echo "You did not make a valid selection!"
fi

# ====

# Create a UID that is not currently in use
echo "Creating an unused UID for new user..."

if [[ $UID -ne 0 ]]; then echo "Please run $0 as root." && exit 1; fi

# Find out the next available user ID
MAXID=$(dscl . -list /Users UniqueID | awk '{print $2}' | sort -ug | tail -1)
USERID=$((MAXID+1))


# Create the user account by running dscl (normally you would have to do each of these commands one
# by one in an obnoxious and time consuming way.
echo "Creating necessary files..."

dscl . -create /Users/$USERNAME
dscl . -create /Users/$USERNAME UserShell /bin/bash
dscl . -create /Users/$USERNAME RealName "$FULLNAME"
dscl . -create /Users/$USERNAME UniqueID "$USERID"
dscl . -create /Users/$USERNAME PrimaryGroupID 20
dscl . -create /Users/$USERNAME NFSHomeDirectory /Users/$USERNAME
dscl . -passwd /Users/$USERNAME $PASSWORD

# set compute host name
sudo scutil --set LocalHostName "$USERNAME"
sudo scutil --set ComputerName "$FULLNAME"
sudo scutil --set HostName "$FULLNAME"

# Add user to any specified groups
echo "Adding user to specified groups..."

for GROUP in $SECONDARY_GROUPS ; do
    dseditgroup -o edit -t user -a $USERNAME $GROUP
done

# Create the home directory
echo "Creating home directory..."
createhomedir -c 2>&1 | grep -v "shell-init"

echo "Created user #$USERID: $USERNAME ($FULLNAME)"

#############################
# Password Policy Settings ##
#Remove Password Policy Settings##
## run pwpolicy -clearaccountpolicies ###
#############################

MAX_FAILED=5                   # 5 max failed logins before locking
LOCKOUT=120                    # 2min lockout
PW_EXPIRE=90                    # 60 days password expiration
MIN_LENGTH=8                    # at least 8 chars for password
MIN_NUMERIC=1                   # at least 1 number in password
MIN_ALPHA_LOWER=1               # at least 1 lower case letter in password
MIN_UPPER_ALPHA=1               # at least 1 upper case letter in password
MIN_SPECIAL_CHAR=1             # at least 1 special character in password
PW_HISTORY=5                   # remember last 5 passwords

exemptAccount1="admin"          #Exempt account used for remote management. CHANGE THIS TO YOUR EXEMPT ACCOUNT



if [ $PW_EXPIRE -lt "1" ]; 
then
    echo "PW EXPIRE TIME CAN NOT BE 0 or less."
    exit 1
fi

for user in $(dscl . list /Users UniqueID | awk '$2 >= 500 {print $1}'); do
    if [ "$user" != "$exemptAccount1" ]; then

    #Check if current plist is installed by comparing the current variables to the new ones

    #PW_History
    currentPwHistory=$(sudo pwpolicy -u "$user" -getaccountpolicies | grep "<string>Does not match any of last $PW_HISTORY passwords</string>" |  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' )
    newPwHistory="<string>Does not match any of last $PW_HISTORY passwords</string>"

    #MIN_SPECIAL_CHAR
    currentMinSpecialChar=$(sudo pwpolicy -u "$user" -getaccountpolicies | grep "<string>policyAttributePassword matches '(.*[^a-zA-Z0-9].*){$MIN_SPECIAL_CHAR,}+'</string>" |  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' )
    newMinSpecialChar="<string>policyAttributePassword matches '(.*[^a-zA-Z0-9].*){$MIN_SPECIAL_CHAR,}+'</string>"

    #MIN_UPPER_ALPHA
    currentUpperLimit=$(sudo pwpolicy -u "$user" -getaccountpolicies | grep "<string>policyAttributePassword matches '(.*[A-Z].*){$MIN_UPPER_ALPHA,}+'</string>" |  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' )
    newUpperLimit="<string>policyAttributePassword matches '(.*[A-Z].*){$MIN_UPPER_ALPHA,}+'</string>"

    #MIN_ALPHA_LOWER
    currentLowerLimit=$(sudo pwpolicy -u "$user" -getaccountpolicies | grep "<string>policyAttributePassword matches '(.*[a-z].*){$MIN_ALPHA_LOWER,}+'</string>" |  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' )
    newLowerLimit="<string>policyAttributePassword matches '(.*[a-z].*){$MIN_ALPHA_LOWER,}+'</string>"

    #MIN_NUMERIC
    currentNumLimit=$(sudo pwpolicy -u "$user" -getaccountpolicies | grep "<string>policyAttributePassword matches '(.*[0-9].*){$MIN_NUMERIC,}+'</string>" |  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' )
    newNumLimit="<string>policyAttributePassword matches '(.*[0-9].*){$MIN_NUMERIC,}+'</string>"

    #MIN_LENGTH
    currentMinLength=$(sudo pwpolicy -u "$user" -getaccountpolicies | grep "<string>policyAttributePassword matches '.{$MIN_LENGTH,}+'</string>" |  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' )
    newMinLength="<string>policyAttributePassword matches '.{$MIN_LENGTH,}+'</string>"

    #PW_EXPIRE
    currentPwExpire=$(sudo pwpolicy -u "$user" -getaccountpolicies | grep "<string>Change every $PW_EXPIRE days</string>" |  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' )
    newPwExpire="<string>Change every $PW_EXPIRE days</string>"

    #LOCKOUT
    currentLockOut=$(sudo pwpolicy -u "$user" -getaccountpolicies | grep "<integer>$LOCKOUT</integer>" |  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' )
    newLockOut="<integer>$LOCKOUT</integer>"

    #MAX_FAILED
    currentMaxFailed=$(sudo pwpolicy -u "$user" -getaccountpolicies | grep "<integer>$MAX_FAILED</integer>" |  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' )
    newMaxFailed="<integer>$MAX_FAILED</integer>"


    isPlistNew=0

    if [ "$currentPwHistory" == "$newPwHistory" ]; then
      echo "PW_History is the same"
    else 
      echo "PW_History is NOT the same"
      echo "current: $currentPwHistory"
      echo "new: $newPwHistory"
      isPlistNew=1
    fi

    if [ "$currentMinSpecialChar" == "$newMinSpecialChar" ]; then
      echo "MIN_SPECIAL_CHAR is the same"
    else 
      echo "MIN_SPECIAL_CHAR is NOT the same"
      echo "current: $currentMinSpecialChar"
      echo "new: $newMinSpecialChar"
      isPlistNew=1
    fi

    if [ "$currentUpperLimit" == "$newUpperLimit" ]; then
      echo "MIN_UPPER_ALPHA is the same"
    else 
      echo "MIN_UPPER_ALPHA is NOT the same"
      echo "current: $currentUpperLimit"
      echo "new: $newUpperLimit"
      isPlistNew=1
    fi

    if [ "$currentLowerLimit" == "$newLowerLimit" ]; then
      echo "MIN_ALPHA_LOWER is the same"
    else 
      echo "MIN_ALPHA_LOWER is NOT the same"
      echo "current: $currentLowerLimit"
      echo "new: $newLowerLimit"  
      isPlistNew=1
    fi

    if [ "$currentNumLimit" == "$newNumLimit" ]; then
      echo "MIN_NUMERIC is the same"
    else 
      echo "MIN_NUMERIC is NOT the same"
      echo "current: $currentNumLimit"
      echo "new: $newNumLimit"  
      isPlistNew=1
    fi

    if [ "$currentMinLength" == "$newMinLength" ]; then
      echo "MIN_LENGTH is the same"
    else 
      echo "MIN_LENGTH is NOT the same"
      echo "current: $currentMinLength"
      echo "new: $newMinLength"  
      isPlistNew=1
    fi

    if [ "$currentPwExpire" == "$newPwExpire" ]; then
      echo "PW_Expire is the same"
    else 
      echo "PW_Expire is NOT the same"
      echo "current: $currentPwExpire"
      echo "new: $newPwExpire"    
      isPlistNew=1
    fi

    if [ "$currentLockOut" == "$newLockOut" ]; then
      echo "LOCKOUT is the same"
    else 
      echo "LOCKOUT is NOT the same"
      echo "current: $currentLockOut"
      echo "new: $newLockOut"    
      isPlistNew=1
    fi

    if [ "$currentMaxFailed" == "$newMaxFailed" ]; then
      echo "MAX_FAILED is the same"
    else 
      echo "MAX_FAILED is NOT the same"
      echo "current: $currentMaxFailed"
      echo "new: $newMaxFailed" 
      isPlistNew=1
    fi




    if [ "$isPlistNew" -eq "1" ]; then


    # Creates plist using variables above
    echo "<dict>
    <key>policyCategoryAuthentication</key>
      <array>
      <dict>
        <key>policyContent</key>
        <string>(policyAttributeFailedAuthentications &amp;amp;amp;amp;amp;lt; policyAttributeMaximumFailedAuthentications) OR (policyAttributeCurrentTime &amp;amp;amp;amp;amp;gt; (policyAttributeLastFailedAuthenticationTime + autoEnableInSeconds))</string>
        <key>policyIdentifier</key>
        <string>Authentication Lockout</string>
        <key>policyParameters</key>
      <dict>
      <key>autoEnableInSeconds</key>
      <integer>$LOCKOUT</integer>
      <key>policyAttributeMaximumFailedAuthentications</key>
      <integer>$MAX_FAILED</integer>
      </dict>
    </dict>
    </array>


    <key>policyCategoryPasswordChange</key>
      <array>
      <dict>
        <key>policyContent</key>
        <string>policyAttributeCurrentTime &amp;amp;amp;amp;amp;gt; policyAttributeLastPasswordChangeTime + (policyAttributeExpiresEveryNDays * 24 * 60 * 60)</string>
        <key>policyIdentifier</key>
        <string>Change every $PW_EXPIRE days</string>
        <key>policyParameters</key>
        <dict>
        <key>policyAttributeExpiresEveryNDays</key>
          <integer>$PW_EXPIRE</integer>
        </dict>
      </dict>
      </array>


      <key>policyCategoryPasswordContent</key>
    <array>
      <dict>
      <key>policyContent</key>
        <string>policyAttributePassword matches '.{$MIN_LENGTH,}+'</string>
      <key>policyIdentifier</key>
        <string>Has at least $MIN_LENGTH characters</string>
      <key>policyParameters</key>
      <dict>
        <key>minimumLength</key>
        <integer>$MIN_LENGTH</integer>
      </dict>
      </dict>


      <dict>
      <key>policyContent</key>
        <string>policyAttributePassword matches '(.*[0-9].*){$MIN_NUMERIC,}+'</string>
      <key>policyIdentifier</key>
        <string>Has a number</string>
      <key>policyParameters</key>
      <dict>
      <key>minimumNumericCharacters</key>
        <integer>$MIN_NUMERIC</integer>
      </dict>
      </dict>


      <dict>
      <key>policyContent</key>
        <string>policyAttributePassword matches '(.*[a-z].*){$MIN_ALPHA_LOWER,}+'</string>
      <key>policyIdentifier</key>
        <string>Has a lower case letter</string>
      <key>policyParameters</key>
      <dict>
      <key>minimumAlphaCharactersLowerCase</key>
        <integer>$MIN_ALPHA_LOWER</integer>
      </dict>
      </dict>


      <dict>
      <key>policyContent</key>
        <string>policyAttributePassword matches '(.*[A-Z].*){$MIN_UPPER_ALPHA,}+'</string>
      <key>policyIdentifier</key>
        <string>Has an upper case letter</string>
      <key>policyParameters</key>
      <dict>
      <key>minimumAlphaCharacters</key>
        <integer>$MIN_UPPER_ALPHA</integer>
      </dict>
      </dict>


      <dict>
      <key>policyContent</key>
        <string>policyAttributePassword matches '(.*[^a-zA-Z0-9].*){$MIN_SPECIAL_CHAR,}+'</string>
      <key>policyIdentifier</key>
        <string>Has a special character</string>
      <key>policyParameters</key>
      <dict>
      <key>minimumSymbols</key>
        <integer>$MIN_SPECIAL_CHAR</integer>
      </dict>
      </dict>


      <dict>
      <key>policyContent</key>
        <string>none policyAttributePasswordHashes in policyAttributePasswordHistory</string>
      <key>policyIdentifier</key>
        <string>Does not match any of last $PW_HISTORY passwords</string>
      <key>policyParameters</key>
      <dict>
        <key>policyAttributePasswordHistoryDepth</key>
        <integer>$PW_HISTORY</integer>
      </dict>
      </dict>

    </array>
    </dict>" > /private/var/tmp/pwpolicy.plist #save the plist temp

    chmod 777 /private/var/tmp/pwpolicy.plist


        pwpolicy -u $user -clearaccountpolicies
        pwpolicy -u $user -setaccountpolicies /private/var/tmp/pwpolicy.plist
        fi
    fi
done

rm /private/var/tmp/pwpolicy.plist

echo "Password policy successfully applied. Run \"sudo pwpolicy -u <user> -getaccountpolicies\" to see it."
exit 0
