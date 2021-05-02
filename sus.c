#include <stdio.h>
#include <stdlib.h>

#include <termios.h>

#include <signal.h>

#include <string.h>

#define _XOPEN_SOURCE

#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <shadow.h>

#include <errno.h>

#define MAX_PASSWORD 3

// TODO: Add pipe support

void get_password(char *password);

void cats(char **str, const char *str2);

int CheckIfInGroup(const char* string);

int GetUID(const char* username, uid_t* uid);
void PrintHelp(); void CreatePasswordMessage();

int CheckPassword(char* password);
int AskPassword();

int uid = 0;

int command_start = 1;

char* command_name;

struct termios old_terminal;

void intHandler(int dummy) {
	tcsetattr(STDIN_FILENO, TCSANOW, &old_terminal);
	puts("Cancelled.");
	exit(0);
}

int main(int argc, char** argv) {
	struct rule *rule;
	char **envp;

	if (CheckIfInGroup("wheel") != 1) {
		puts("ERROR: Not in the wheel group.");
		return 0;
	}

	tcgetattr(STDIN_FILENO, &old_terminal);

	signal(SIGINT, intHandler);

	command_name = malloc((1 + strlen(argv[0])) * sizeof(char));
	strcpy(command_name, argv[0]);

	if (argc < 2) {
		PrintHelp();
		return 0;
	}
	
	if (AskPassword() != 1) {
		puts("ERROR: Too many attempts.");
		return 1;
	}

	char username[32];
	username[0] = '\0';

	if (argv[1][0] == '-') {
		// - specified. Check if user is in next argument or 
		// in the same argument as the switch.
		if (strlen(argv[1]) > 1) {
			if (strlen(argv[1]) > 34) {
				puts("ERROR: Username limit reached!");
				return 1;
			}
			strcpy(username, argv[1]);
			command_start = 2;
		} else {
			if (strlen(argv[2]) > 33) {
				puts("ERROR: Username limit reached!");
				return 1;
			}
			strcpy(username, argv[2]);
			command_start = 3;
		}

		if (username[0] == '-')
			memmove(username, username+1, strlen(username));

	}

	char* command = "";
	for (int i = command_start; i < argc; i++) {
		cats(&command, argv[i]);
		cats(&command, " ");
	}

	command[strlen(command)-1] = '\0';
	
	if (username[0] == '\0')
		uid = 0;
	else
		if (GetUID(username, &uid) == -1) {
			printf("ERROR: Could not find username: %s", username);
			return 1;
		}

	if (fork() == 0) {
		setuid(uid);
		system(command);
	}

	return 0;
}

int GetUID(const char* username, uid_t* uid) { struct passwd *pw; pw = getpwnam(username); if (pw != NULL) { *uid = pw->pw_uid;
		return 1;
	}

	return -1;
}

int CheckIfInGroup(const char* string) {
	int ngroups_max;
	ngroups_max = sysconf(_SC_NGROUPS_MAX);

	int groups = getgroups(0, NULL);

	gid_t list[groups];

	int ngroups = getgroups(groups, list);

	if (ngroups < 0)
		return -1;
	
	for (int i = 0; i < groups; i++) {
		struct group *grp;
		grp = getgrgid(list[i]);
		if (grp == NULL)
			return -1;
		if (strcmp(grp->gr_name, "wheel") == 0)
			return 1;

	}
	
	return -1;
}

void PrintHelp() {
	printf("Usage: %s [- user] command\n", command_name);
}

int AskPassword() {
	for (int i=0; i<MAX_PASSWORD; i++) {
		printf("Password: ");
		char password[BUFSIZ];
		get_password(password);

		int res = CheckPassword(password);
		if (res == 0)
			return 1;
		else
			CreatePasswordMessage();
	}
}

int CheckPassword(char* password) {
	struct spwd* shadow_entry;
	struct passwd *pa = getpwuid(getuid());
	char *p, *correct, *supplied, *salt;
	shadow_entry = getspnam(pa->pw_name);
	if (shadow_entry == NULL) 
		return 2;
	correct = shadow_entry->sp_pwdp;
	salt = strdup(correct);
	if (salt == NULL) 
		return 3;
	p = strchr(salt + 1, '$');
	if (p == NULL) 
		return 4;
	p = strchr(p + 1, '$');
	if (p == NULL) 
		return 5;
	p[1] = 0;

	supplied = crypt(password, salt);
	if (supplied == NULL) 
		return 6;
	return !!strcmp(supplied, correct);
}

void CreatePasswordMessage() {
	puts("Incorrect password! Try again.");
}

void cats(char **str, const char *str2) {
	char *tmp = NULL;
	
	// Reset *str
	if ( *str != NULL && str2 == NULL ) {
		free(*str);
		*str = NULL;
		return;
	}
	
	// Initial copy
	if (*str == NULL) {
		*str = calloc( strlen(str2)+1, sizeof(char) );
		memcpy( *str, str2, strlen(str2) );
	}
	else { // Append
		tmp = calloc( strlen(*str)+1, sizeof(char) );
		memcpy( tmp, *str, strlen(*str) );
		*str = calloc( strlen(*str)+strlen(str2)+1, sizeof(char) );
		memcpy( *str, tmp, strlen(tmp) );
		memcpy( *str + strlen(*str), str2, strlen(str2) );
		free(tmp);
	}

}

void get_password(char *password)
{
	static struct termios new_terminal;
	
	new_terminal = old_terminal;
	new_terminal.c_lflag &= ~(ECHO);
	
	tcsetattr(STDIN_FILENO, TCSANOW, &new_terminal);
	
	if (fgets(password, BUFSIZ, stdin) == NULL)
	    password[0] = '\0';
	else
	    password[strlen(password)-1] = '\0';

	putchar('\n');
	
	tcsetattr(STDIN_FILENO, TCSANOW, &old_terminal);
}

