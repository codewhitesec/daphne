#include <stdio.h>

/*
 * Function: str_to_hex
 * ----------------------------
 *   Convert a string to hex representation.
 *
 *   Parameters:
 *     buffer       buffer to store the hex representation in
 *     str          string to convert
 *
 *   Returns:
 *     void
 */
void str_to_hex(char* buffer, char* str)
{
    char* pos = buffer;

    for (int ctr = 0; ctr < strlen(str); ctr++)
    {
        sprintf(pos, "%02X", str[ctr]);
        pos += 2;
    }
}

/*
 * Function: str_arr_to_hex
 * ----------------------------
 *   Convert an array of strings into hex representation.
 *   In the final hex string, each array item is separated
 *   by a null byte.
 *
 *   Parameters:
 *     buffer       buffer to store the hex representation in
 *     len          length of the string array
 *     str_arr      string array
 *
 *   Returns:
 *     void
 */
void str_arr_to_hex(char* buffer, int len, char** str_arr)
{
    char* pos = buffer;

    for (int ctr = 0; ctr < len; ctr++)
    {
        for (int cts = 0; cts < strlen(str_arr[ctr]); cts++)
        {
            sprintf(pos, "%02X", str_arr[ctr][cts]);
            pos += 2;
        }

        if (ctr != len - 1)
        {
            sprintf(pos, "%02X", 0x00);
            pos += 2;
        }
    }
}


/*
 * Function: str_replace
 * ----------------------------
 *   String replace function copied from https://stackoverflow.com/a/779960
 *
 *   Parameters:
 *     orig         original string to replace on
 *     rep          string that should be replaced
 *     with         string to replace with
 *
 *   Returns:
 *     buffer that contains the result string. Needs to be freed by the
 *     caller
 */
char* str_replace(char* orig, char* rep, char* with)
{
    char *result;
    char *ins;
    char *tmp;
    int len_rep;
    int len_with;
    int len_front;
    int count;

    if (!orig || !rep)
    {
        return NULL;
    }

    len_rep = strlen(rep);

    if (len_rep == 0)
    {
        return NULL;
    }

    if (!with)
    {
        with = "";
    }

    len_with = strlen(with);
    ins = orig;

    for (count = 0; tmp = strstr(ins, rep); ++count)
    {
        ins = tmp + len_rep;
    }

    tmp = result = malloc(strlen(orig) + (len_with - len_rep) * count + 1);

    if (!result)
    {
        return NULL;
    }

    while (count--)
    {
        ins = strstr(orig, rep);
        len_front = ins - orig;
        tmp = strncpy(tmp, orig, len_front) + len_front;
        tmp = strcpy(tmp, with) + len_with;
        orig += len_front + len_rep;
    }

    strcpy(tmp, orig);
    return result;
}
