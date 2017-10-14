#include "FingerPrintDB.h"
#if defined(_MSC_VER)
#include <file\FileHelper.h>
#include <string\StringHelper.h>
#elif defined(__GNUC__)
#include <file/FileHelper.h>
#include <string/StringHelper.h>
#include <string.h>
#include <memory>
#include <math.h> 
#else
#error unsupported compiler
#endif
#include <algorithm>

#ifdef min
#undef min
#endif // min
#ifdef max
#undef max
#endif // max

#if defined(_MSC_VER)
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#elif defined(__GNUC__)
#define strncat_s strncat
#endif

bool FingerPrintDB::InitFromFile(const std::string &file)
{
    std::string file_content = FileHelper::GetFileContent(file);
    return InitFromContent(file_content);
}

bool FingerPrintDB::InitFromContent(const std::string &file_content)
{
    this->MatchPoints = FingerPrint();
    this->prints.clear();

    if (file_content.empty()) {
        return false;
    }

    std::vector<std::string> temp_lines = StringHelper::split(file_content, "\n");
    std::vector<std::string> lines;
    for (auto it = temp_lines.begin(); it != temp_lines.end(); it++) {
        if (it->empty()) {
            lines.emplace_back(*it);
        }
        else {
            std::vector<std::string> tmp = StringHelper::split(*it, "#");
            lines.emplace_back(StringHelper::trim(StringHelper::trim(tmp[0])));
        }
    }
    temp_lines.clear();

    bool parsing_match_points = false;
    for (auto it = lines.begin(); it != lines.end(); it++) {
        std::string line = *it;
        if (line.empty()) {
            continue;
        }
        if (strncasecmp(line.c_str(), "FingerPrint", 11) == 0) {
            parsing_match_points = false;
        }
        else if (strncasecmp(line.c_str(), "MatchPoints", 11) == 0) {
            parsing_match_points = true;
        }
        else {
            continue;
        }

        FingerPrint *current = NULL;
        if (parsing_match_points) {
            current = &this->MatchPoints;
            if (!current->match) {
                return false;
            }
        }
        else {
            std::string os_name = std::string(line, 11);
            if (os_name.empty()) {
                continue;
            }
            this->prints.emplace_back(FingerPrint());
            current = &this->prints.back();
            if (!current->match) {
                return false;
            }
            current->match->os_name = StringHelper::getstaticstring(os_name);
        }

        while (++it != lines.end())
        {
            std::string next_line = *it;
            if (next_line.empty()) {
                break;
            }
            if (strncasecmp(next_line.c_str(), "FingerPrint ", 12) == 0) {
                it--;
                break;
            }
            if (strncasecmp(next_line.c_str(), "Class ", 6) == 0) {
                std::string class_line = std::string(next_line, 6);
                if (class_line.empty()) {
                    continue;
                }
                std::vector<std::string> tmp = StringHelper::split(class_line, "|");
                if (tmp.size() != 4) {
                    continue;
                }
                OSClassification os_class;
                os_class.OS_Vendor = StringHelper::getstaticstring(StringHelper::trim(tmp[0]));
                os_class.OS_Family = StringHelper::getstaticstring(StringHelper::trim(tmp[1]));
                os_class.OS_Generation = StringHelper::getstaticstring(StringHelper::trim(tmp[2]));
                os_class.Device_Type = StringHelper::getstaticstring(StringHelper::trim(tmp[3]));
                current->match->os_class.emplace_back(os_class);
                continue;
            }
            if (strncasecmp(next_line.c_str(), "CPE ", 4) == 0) {
                std::string cpe_line = std::string(next_line, 4);
                if (cpe_line.empty()) {
                    continue;
                }
                if (current->match->os_class.empty()) {
                    continue;
                }
                OSClassification& osc = current->match->os_class.back();
                osc.cpe.emplace_back(StringHelper::getstaticstring(cpe_line));
                continue;
            }
            std::vector<std::string> tmp = StringHelper::split(next_line, "(");
            if (tmp.size() != 2) {
                continue;
            }
            std::string test_name = StringHelper::trim(tmp[0]);
            if (test_name.empty()) {
                continue;
            }
            FingerTest test;
            test.name = StringHelper::getstaticstring(test_name);
            if (!tmp[1].empty())
            {
                std::string avals_line = StringHelper::split(tmp[1], ")")[0];
                std::vector<std::string> avals = StringHelper::split(avals_line, "%");
                for (auto aval : avals) {
                    std::vector<std::string> attr_vale = StringHelper::split(aval, "=");
                    if (attr_vale.size() != 2) {
                        continue;
                    }
                    AVal av;
                    av.attribute = StringHelper::getstaticstring(StringHelper::trim(attr_vale[0]));
                    av.value = StringHelper::getstaticstring(StringHelper::trim(attr_vale[1]));
                    test.results.emplace_back(av);
                }
            }
            current->tests.emplace_back(test);
        }
        current->sort();
    }
    return true;
}


FingerPrintResults FingerPrintDB::MatchFingerprint(const FingerPrint &fp, double accuracy_threshold)
{
    FingerPrintResults r;
    double FPR_entrance_requirement = accuracy_threshold;
    FingerPrint FP_copy;
    size_t max_prints = MAX_FP_RESULTS;
    size_t idx;
    double tmp_acc = 0.0; /* These are temp buffers for list swaps */
    FingerMatch *tmp_FP = NULL;

    if (FPR_entrance_requirement < 0.00000001 || FPR_entrance_requirement > 1.0) {
        FPR_entrance_requirement = OSSCAN_GUESS_THRESHOLD;
    }

    FP_copy = fp;
    FP_copy.sort();

    r.overall_results = OSSCAN_SUCCESS;
    for (auto current_os = this->prints.begin(); current_os != this->prints.end(); current_os++) {
        if (!current_os->match) {
            continue;
        }
        double acc = CompareFingerprints(*current_os, FP_copy);
        if (acc < FPR_entrance_requirement) {
            continue;
        }
        int skipfp = 0;
        for (idx = 0; idx < r.matches.size(); idx++) {
            if (strcmp(r.matches[idx].second->os_name, current_os->match->os_name) == 0) {
                if (r.matches[idx].first >= acc) {
                    skipfp = 1; /* Skip it -- a higher version is already in list */
                }
                else {
                    /* rm the match*/
                    r.matches.erase(r.matches.begin() + idx);
                }
                break;
            }
        }

        if (skipfp) {
            continue;
        }

        /* First we check whether we have overflowed with perfect matches */
        if (acc == 1) {
            if (r.num_perfect_matches == max_prints) {
                r.overall_results = OSSCAN_TOOMANYMATCHES;
                return r;
            }
            r.num_perfect_matches++;
        }

        /* Now we add the sucker to the list */
        r.matches.emplace_back(std::pair<double, std::shared_ptr<FingerMatch>>(acc, current_os->match));
        qsort(&*r.matches.begin(), r.matches.size(), sizeof(*r.matches.begin()), [](const void *a, const void *b) {
            std::pair<double, std::shared_ptr<FingerMatch>> *left = (std::pair<double, std::shared_ptr<FingerMatch>> *)a;
            std::pair<double, std::shared_ptr<FingerMatch>> *right = (std::pair<double, std::shared_ptr<FingerMatch>> *)b;
            if (left->first == right->first) {
                return 0;
            }
            if (left->first < right->first) {
                return 1;
            }
            return -1;
        });
        /* If we are over max_prints, one was shoved off list */
        if (r.matches.size() > max_prints) {
            r.matches.erase(r.matches.end() - 1);
        }

        /* Calculate the new min req. */
        if (r.matches.size() == max_prints) {
            FPR_entrance_requirement = r.matches.back().first + 0.00001;
        }
    }

    if (r.matches.size() == 0 && r.overall_results == OSSCAN_SUCCESS) {
        r.overall_results = OSSCAN_NOMATCHES;
    }
  
    return r;
}

/*
Compares 2 fingerprints and calculate its similarity level. the referenceFP should be from this->prints
referenceFP(in): should be from this->prints
observedFP(in): compare FP
return the similarity level
*/
double FingerPrintDB::CompareFingerprints(const FingerPrint &referenceFP, const FingerPrint &observedFP)
{
    std::vector<FingerTest>::const_iterator current_ref, prev_ref;
    std::vector<FingerTest>::const_iterator current_fp, prev_fp;
    std::vector<FingerTest>::const_iterator current_points;
    unsigned long num_subtests = 0, num_subtests_succeeded = 0;
    unsigned long new_subtests = 0, new_subtests_succeeded = 0;

    /* We rely on tests being sorted by name. */
    prev_ref = referenceFP.tests.end();
    prev_fp = observedFP.tests.end();
    current_ref = referenceFP.tests.begin();
    current_fp = observedFP.tests.begin();
    current_points = this->MatchPoints.tests.begin();
    while (current_ref != referenceFP.tests.end() && current_fp != observedFP.tests.end()) {
        if (!current_ref->name || !current_fp->name) {
            break;
        }

        int d = strcmp(current_ref->name, current_fp->name);
        if (d == 0) {
            new_subtests = new_subtests_succeeded = 0;
            for (; current_points != this->MatchPoints.tests.end(); current_points++) {
                if (strcmp(current_ref->name, current_points->name) == 0) {
                    break;
                }
            }
            if (current_points == this->MatchPoints.tests.end()) {
                //error occured, should not occur
                return 0;
            }

            AValMatch(*current_ref, *current_fp, *current_points, &new_subtests, &new_subtests_succeeded);
            num_subtests += new_subtests;
            num_subtests_succeeded += new_subtests_succeeded;
        }

        if (d <= 0) {
            prev_ref = current_ref;
            current_ref++;
        }
        if (d >= 0) {
            prev_fp = current_fp;
            current_fp++;
        }
    }

    return (num_subtests && (num_subtests_succeeded <= num_subtests)) ? (num_subtests_succeeded / (double)num_subtests) : 0;
}

/*
TEST a FingerTest(like SEQ(SP=0-5%GCD=51E80C|A3D018|F5B824|147A030|199883C%ISR=C8-D2%TI=I|RD%CI=I%II=RI%SS=S%TS=U) ) match level, if perfect match, then return 1.
reference(in): read from file in Fingerprint, like parse SEQ(SP=0-5%GCD=51E80C|A3D018|F5B824|147A030|199883C%ISR=C8-D2%TI=I|RD%CI=I%II=RI%SS=S%TS=U)
fprint(in): get from packet,
points(in): read from file in MatchPoints, like parse SEQ(SP=25%GCD=75%ISR=25%TI=100%CI=50%II=100%SS=80%TS=100), the number is the subtests
num_subtests(out): in points para which the number add
num_subtests_succeeded(out): releate to num_subtests, when aval match, the num add
return 0 for num_subtests equal num_subtests_succeeded
*/
int FingerPrintDB::AValMatch(const FingerTest &reference, const FingerTest &fprint, const FingerTest &points,
    unsigned long *num_subtests, unsigned long *num_subtests_succeeded)
{
    std::vector<AVal>::const_iterator current_ref, prev_ref;
    std::vector<AVal>::const_iterator current_fp, prev_fp;
    std::vector<AVal>::const_iterator current_points;
    int subtests = 0, subtests_succeeded = 0;
    int pointsThisTest = 1;

    /* We rely on AVals being sorted by attribute. */
    prev_ref = reference.results.end();
    prev_fp = fprint.results.end();
    current_ref = reference.results.begin();
    current_fp = fprint.results.begin();
    current_points = points.results.begin();
    while (current_ref != reference.results.end() && current_fp != fprint.results.end()) {
        int d = 0;
        d = strcmp(current_ref->attribute, current_fp->attribute);
        if (d == 0) {
            for (; current_points != points.results.end(); current_points++) {
                if (strcmp(current_ref->attribute, current_points->attribute) == 0) {
                    break;
                }
            }
            if (current_points == points.results.end()) {
                return 0;
            }
            char *endptr = NULL;
            pointsThisTest = strtol(current_points->value, &endptr, 10);
            if (*endptr != '\0' || pointsThisTest < 0) {
                return 0;
            }

            subtests += pointsThisTest;
            if (ExprMatch(current_fp->value, current_ref->value)) {
                subtests_succeeded += pointsThisTest;
            }
        }

        if (d <= 0) {
            prev_ref = current_ref;
            current_ref++;
        }
        if (d >= 0) {
            prev_fp = current_fp;
            current_fp++;
        }
    }

    if (num_subtests) {
        *num_subtests += subtests;
    }
    if (num_subtests_succeeded) {
        *num_subtests_succeeded += subtests_succeeded;
    }
    return (subtests == subtests_succeeded) ? 1 : 0;
}

/* Compare an observed value (e.g. "45" in hex) against an OS DB expression (e.g.
"3B-47" or "8|A" or ">10"). Return true iff there's a match. The syntax uses
< (less than)
> (greater than)
+ (non-zero)
| (or)
- (range)
& (and)
No parentheses are allowed. */
bool FingerPrintDB::ExprMatch(const char *val, const char *expr)
{
    int andexp = 0, orexp = 0, expchar = '|', numtrue = 0;
    char exprcpy[512];
    char *p = NULL, *q = NULL, *q1 = NULL;  /* OHHHH YEEEAAAAAHHHH!#!@#$!% */
    unsigned int val_num = 0, expr_num = 0, expr_num1 = 0;

    if (val == NULL || expr == NULL) {
        return false;
    }

    memcpy(exprcpy, expr, std::min((int)sizeof(exprcpy) - 1, (int)strlen(expr) + 1));
    exprcpy[sizeof(exprcpy) - 1] = 0;
    p = exprcpy;
    if (strchr(expr, '|')) {
        orexp = 1; expchar = '|';
    }
    else {
        andexp = 1; expchar = '&';
    }

    do {
        char *endptr = NULL;
        q = strchr(p, expchar);
        if (q) {
            *q = '\0';
        }
        //do each string that split by '|' or '&'
        if (strcmp(p, "+") == 0) {
            //not zero
            if (!*val) {
                if (andexp) {
                    return false;
                }
            }
            else {
                val_num = strtol(val, &endptr, 16);
                if (val_num == 0 || *endptr) {
                    if (andexp) {
                        return false;
                    }
                }
                else {
                    numtrue++;
                }
            }
        }
        else if (*p == '<' && isxdigit((int)(unsigned char)p[1])) {
            //littel than
            if (!*val) {
                if (andexp) {
                    return false;
                }
            }
            expr_num = strtol(p + 1, &endptr, 16);
            val_num = strtol(val, &endptr, 16);
            if (val_num >= expr_num || *endptr) {
                if (andexp) {
                    return false;
                }
            }
            else {
                numtrue++;
            }
        }
        else if (*p == '>' && isxdigit((int)(unsigned char)p[1])) {
            //great than
            if (!*val) {
                if (andexp) {
                    return false;
                }
            }
            expr_num = strtol(p + 1, &endptr, 16);
            val_num = strtol(val, &endptr, 16);
            if (val_num <= expr_num || *endptr) {
                if (andexp) {
                    return false;
                }
            }
            else {
                numtrue++;
            }
        }
        else if (((q1 = strchr(p, '-')) != NULL) && isxdigit((int)(unsigned char)p[0]) && isxdigit((int)(unsigned char)q1[1])) {
            //in range
            if (!*val) {
                if (andexp) {
                    return false;
                }
            }
            *q1 = '\0';
            expr_num = strtol(p, NULL, 16);
            expr_num1 = strtol(q1 + 1, NULL, 16);
            if (expr_num1 < expr_num) {
                int tmp = expr_num1;
                expr_num1 = expr_num;
                expr_num = tmp;
            }
            val_num = strtol(val, &endptr, 16);
            if (val_num < expr_num || val_num > expr_num1 || *endptr) {
                if (andexp) {
                    return false;
                }
            }
            else {
                numtrue++;
            }
        }
        else {
            //string equal
            if (strcmp(p, val)) {
                if (andexp) {
                    return false;
                }
            }
            else {
                numtrue++;
            }
        }

        if (numtrue && orexp) {
            break;
        }
        if (q) {
            p = q + 1;
        }
    } while (q);

    return numtrue != 0;
}

int OSClassificationResults::AddToCharArrayIfNew(const char *arr[], int *numentries, int arrsize, const char *candidate)
{
    int i = 0;

    // First lets see if the member already exists
    for (i = 0; i < *numentries; i++) {
        if (strcmp(arr[i], candidate) == 0)
            return *numentries;
    }

    // Not already there... do we have room for a new one?
    if (*numentries >= arrsize)
        return -1;

    // OK, not already there and we have room, so we'll add it.
    arr[*numentries] = candidate;
    (*numentries)++;
    return *numentries;
}

#define MAX_OS_CLASSMEMBERS 8
std::string OSClassificationResults::str(bool guess)
{
    int classno = 0, cpeno, familyno;
    unsigned int i;
    int overflow = 0;             /* Whether we have too many devices to list */
    const char *types[MAX_OS_CLASSMEMBERS];
    const char *cpes[MAX_OS_CLASSMEMBERS];
    char fullfamily[MAX_OS_CLASSMEMBERS][128];    // "[vendor] [os family]"
    double familyaccuracy[MAX_OS_CLASSMEMBERS];   // highest accuracy for this fullfamily
    char familygenerations[MAX_OS_CLASSMEMBERS][96];      // example: "4.X|5.X|6.X"
    int numtypes = 0, numcpes = 0, numfamilies = 0;
    char tmpbuf[1024];
    char info_buf[1024];
    std::string info;

    for (i = 0; i < MAX_OS_CLASSMEMBERS; i++) {
        familygenerations[i][0] = '\0';
        familyaccuracy[i] = 0.0;
    }

    if (overall_results == OSSCAN_SUCCESS) {

        // Now to create the fodder for normal output
        for (auto it = osc.begin(); it != osc.end(); it++, classno++) {
            if ((!guess && classno >= osc_num_perfect_matches) ||
                it->first <= osc.begin()->first - 0.1 ||
                (it->first < 1.0 && (classno > MAX_OS_CLASSMEMBERS + 1))) {
                break;
            }
            if (AddToCharArrayIfNew(types, &numtypes, MAX_OS_CLASSMEMBERS,
                it->second.Device_Type) == -1) {
                overflow = 1;
            }
            for (i = 0; i < it->second.cpe.size(); i++) {
                if (AddToCharArrayIfNew(cpes, &numcpes, MAX_OS_CLASSMEMBERS,
                    it->second.cpe[i]) == -1) {
                    overflow = 1;
                }
            }

            // If family and vendor names are the same, no point being redundant
            if (strcmp(it->second.OS_Vendor, it->second.OS_Family) == 0) {
                snprintf(tmpbuf, sizeof(tmpbuf), "%s", it->second.OS_Family);
            }
            else {
                snprintf(tmpbuf, sizeof(tmpbuf), "%s %s", it->second.OS_Vendor, it->second.OS_Family);
            }

            // Let's see if it is already in the array
            for (familyno = 0; familyno < numfamilies; familyno++) {
                if (strcmp(fullfamily[familyno], tmpbuf) == 0) {
                    // got a match ... do we need to add the generation?
                    if (it->second.OS_Generation
                        && !strstr(familygenerations[familyno],
                            it->second.OS_Generation)) {
                        int flen = strlen(familygenerations[familyno]);
                        // We add it, preceded by | if something is already there
                        if (flen + 2 + strlen(it->second.OS_Generation) >= sizeof(familygenerations[familyno])) {
                            return info;
                        }
                        if (*familygenerations[familyno]) {
                            strncat_s(familygenerations[familyno], "|", sizeof(familygenerations[familyno]) - flen - 2);
                        }
                        strncat_s(familygenerations[familyno], it->second.OS_Generation, sizeof(familygenerations[familyno]) - flen - 1);
                    }
                    break;
                }
            }

            if (familyno == numfamilies) {
                // Looks like the new family is not in the list yet.  Do we have room to add it?
                if (numfamilies >= MAX_OS_CLASSMEMBERS) {
                    overflow = 1;
                    break;
                }
                // Have space, time to add...
                snprintf(fullfamily[numfamilies], 128, "%s", tmpbuf);
                if (it->second.OS_Generation) {
                    snprintf(familygenerations[numfamilies], 48, "%s", it->second.OS_Generation);
                }
                familyaccuracy[numfamilies] = it->first;
                numfamilies++;
            }
        }

        if (!overflow && numfamilies >= 1) {
            snprintf(info_buf, sizeof(info_buf), "Device type: ");
            info += info_buf;
            for (classno = 0; classno < numtypes; classno++)
            {
                snprintf(info_buf, sizeof(info_buf), "%s%s", types[classno], (classno < numtypes - 1) ? "|" : "");
                info += info_buf;
            }
            snprintf(info_buf, sizeof(info_buf), "\nRunning%s: ", osc_num_perfect_matches == 0 ? " (JUST GUESSING)" : "");
            info += info_buf;
            for (familyno = 0; familyno < numfamilies; familyno++) {
                if (familyno > 0)
                {
                    snprintf(info_buf, sizeof(info_buf), ", ");
                    info += info_buf;
                }
                snprintf(info_buf, sizeof(info_buf), "%s", fullfamily[familyno]);
                info += info_buf;
                if (*familygenerations[familyno])
                {
                    snprintf(info_buf, sizeof(info_buf), " %s", familygenerations[familyno]);
                    info += info_buf;
                }
                if (familyno >= osc_num_perfect_matches)
                {
                    snprintf(info_buf, sizeof(info_buf), " (%.f%%)", floor(familyaccuracy[familyno] * 100));
                    info += info_buf;
                }
            }
            snprintf(info_buf, sizeof(info_buf), "\n");
            info += info_buf;

            if (numcpes > 0) {
                snprintf(info_buf, sizeof(info_buf), "OS CPE:");
                info += info_buf;
                for (cpeno = 0; cpeno < numcpes; cpeno++)
                {
                    snprintf(info_buf, sizeof(info_buf), " %s", cpes[cpeno]);
                    info += info_buf;
                }
                snprintf(info_buf, sizeof(info_buf), "\n");
                info += info_buf;
            }
        }
    }
    return info;
}

/* Return true iff s and t are both NULL or both the same string. */
bool FingerPrintResults::strnulleq(const char *s, const char *t) 
{
    if (s == NULL && t == NULL)
        return true;
    else if (s == NULL || t == NULL)
        return false;
    else
        return strcmp(s, t) == 0;
}

OSClassificationResults FingerPrintResults::GetOSClassification()
{
    OSClassificationResults r;
    int printno = 0;

    r.overall_results = OSSCAN_SUCCESS;

    if (overall_results == OSSCAN_TOOMANYMATCHES) {
        r.overall_results = OSSCAN_TOOMANYMATCHES;
        return r;
    }

    for (auto match : this->matches) {
        if (!match.second) {
            continue;
        }
        for (auto it = match.second->os_class.begin(); it != match.second->os_class.end(); it++, printno++) {
            bool is_in_result = false;
            for (auto osc: r.osc) {
                if (strnulleq(it->OS_Vendor, osc.second.OS_Vendor) &&
                    strnulleq(it->OS_Family, osc.second.OS_Family) &&
                    strnulleq(it->Device_Type, osc.second.Device_Type) &&
                    strnulleq(it->OS_Generation, osc.second.OS_Generation)) {
                    is_in_result = true;
                    break;
                }
            }
            if (is_in_result) {
                continue;
            }

            if (r.osc.size() == MAX_FP_RESULTS) {
                // Out of space ... if the accuracy of this one is 100%, we have a problem
                if (printno < num_perfect_matches) {
                    r.overall_results = OSSCAN_TOOMANYMATCHES;
                }
                return r;
            }

            // We have space, but do we even want this one?  No point
            // including lesser matches if we have 1 or more perfect
            // matches.
            if (r.osc_num_perfect_matches > 0 && printno >= num_perfect_matches) {
                return r;
            }

            // OK, we will add the new class
            r.osc.emplace_back(std::pair<double, OSClassification>(match.first, *it));
            if (printno < num_perfect_matches) {
                r.osc_num_perfect_matches++;
            }
        }
    }

    if (r.osc.size() == 0) {
        r.overall_results = OSSCAN_NOMATCHES;
    }
    return r;
}

std::string FingerPrintResults::str(bool guess)
{
    int i;
    char info_buf[1024];
    std::string info;

    // If the FP can't be submitted anyway, might as well make a guess.
    info = GetOSClassification().str(guess);
    if (overall_results == OSSCAN_SUCCESS && num_perfect_matches <= 8) {
        /* Success, not too many perfect matches. */
        if (num_perfect_matches > 0) {
            snprintf(info_buf, sizeof(info_buf), "OS details: %s", matches[0].second->os_name);
            info += info_buf;
            for (i = 1; i < num_perfect_matches; i++) {
                snprintf(info_buf, sizeof(info_buf), ", %s", matches[i].second->os_name);
                info += info_buf;
            }
            snprintf(info_buf, sizeof(info_buf), "\n");
            info += info_buf;
        }
        else if (guess){
            /* Print the best guesses available */
            snprintf(info_buf, sizeof(info_buf), "Aggressive OS guesses: %s (%.f%%)", matches[0].second->os_name, floor(matches[0].first * 100));
            info += info_buf;
            for (i = 1; i < 10 && (int)matches.size() > i && matches[i].first > matches[0].first - 0.10; i++)
            {
                snprintf(info_buf, sizeof(info_buf), ", %s (%.f%%)", matches[i].second->os_name, floor(matches[i].first * 100));
                info += info_buf;
            }
            snprintf(info_buf, sizeof(info_buf), "\n");
            info += info_buf;
        }
    }
    return info;
}