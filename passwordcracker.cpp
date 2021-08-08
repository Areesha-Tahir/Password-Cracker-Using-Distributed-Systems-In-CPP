/*

Basic Logic:
-In our master machine (process id 0) we will read shadow.txt file and use tokenize function to parse the sentence to get salt and encrypted key
-Then we send the length of salt, length of key, salt and encrypted key to each of the slave processes to use to search for password. 
-We will dynamically divide passwords among the slaves based on password lengths e.g passwords of length 1-2 will go to one process, 3-4 will go to another and so on
-In case of 8(max length) not being divisible by number of processes the remainder will be taken up by the master itself to search. 
-To search a function runs which tests all possible combinations of alph for its allotted length and returns true or false if password found or not.
-If password is found, the slave calls MPI_Abort to stop all other processes from continuing their search. 

NOTE: We tested out code using 4 VMs, 3 slaves and 1 Master however it works best with 1 slave since our laptops do not have enough power to bear so many VMs and 
become unbearably slow. 

Submitted By:
	Aleezeh Usman	18I-0529
	Areesha Tahir	18I-1655
	Faaira Ahmed	18I-0423
	Omer Ihtizaz	18I-0404
*/

#include<stdio.h>
#include<unistd.h>
#include<crypt.h>
#include<string.h>
#include<iostream>
#include <queue>
#include<mpi.h>
#include<fstream>
#include <bits/stdc++.h>
using namespace std;
//==================================================================================================================================
//							FUNCTIONS
//==================================================================================================================================

//Function to tokenize the data we get from shadows file to retrieve salt and encrypted password and remove useless information
void tokenize(string s, string &getsalt, string &gethash, string del = " ")
{
    int start = 0;
    int end = s.find(del);
    int count = 0;
    string id = "$";
    string Salt = "";
    while (count < 3) {						//We are tokenizing based on $ sign so we get 3 tokens
    	if (count == 1){					//First token is ID
    		id += s.substr(start, end - start);
    		id = id + "$";					//append $ to match format
    	}
    	if (count == 2){					//Second token is salt
    		string slt = id ;
        	slt += s.substr(start, end - start);
        	slt = slt + "$";				//append $ to match format
        	Salt = slt;
        }
        start = end + del.size();				
        end = s.find(del, start);				//find position of $ in the string to get the next token which to move start and end forward to get the correct piece of string
        count++;
    }
    string temp = "";
    temp = s.substr(start, end - start);			//get the complete hash value without salt and id
    del = ":";
    end = temp.find(del); 
    start = del.size() - 1;
    gethash = temp.substr(start, end - start); 			
    getsalt = Salt;
    gethash = getsalt + gethash;				//get complete hash value with salt and if as well
}

//Function used to convert character array to a string
string convertToString(char* a, int size)
{
    int i;
    string s = "";
    for (i = 0; i <= size; i++) {
        s = s + a[i];
    }
    return s;
}

//Main logic function which will check all possible passwords by brute force technique and return true when a password is found
//Parameteres: digitstart - digitsend i.e the rangbe of length of password the function should search in
bool PasswordCracker(int digitstart, int digitsend,string salt, string actualencrypt, int procid){

	char testpass[8] = "*******";							//temporary char array to store possible password combinations in
	char alph[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l','m', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};										//alphabets that will be used to generate possible passwords

	int i = digitstart-1;								//So we can dynamically change the range of length of password we are searching for
	for(; i < digitsend-1; i++){							//8 nested loops to create password combinations using alphabets upto 8 characters long						
		for (int dig8 = 0; dig8 < 26 ; dig8++){
			if(i>6){
				testpass[i-7] = alph[dig8];
			}
		for (int dig7 = 0; dig7 < 26 ; dig7++){
			if(i>5){
				testpass[i-6] = alph[dig7];
			}
		for (int dig6 = 0; dig6 < 26 ; dig6++){
			if(i>4){
				testpass[i-5] = alph[dig6];
			}
		for (int dig5 = 0; dig5 < 26 ; dig5++){
			if(i>3){
				testpass[i-4] = alph[dig5];
			}
		for (int dig4 = 0; dig4 < 26 ; dig4++){
			if(i>2){
				testpass[i-3] = alph[dig4];
			}
		for (int dig3 = 0; dig3 < 26 ; dig3++){
			if(i>1){
				testpass[i-2] = alph[dig3];
			}
		for(int dig2 = 0; dig2<26 ; dig2++){
			if(i>0){
				testpass[i-1] = alph[dig2];
			}		
			for(int dig1 = 0; dig1<26 ; dig1++){
				testpass[i] = alph[dig1];
				string passwordoption = convertToString(testpass,i);
				//cout<<"P"<<procid<<":CURRENT -> "<<passwordoption<<endl;			//print each password combination
				string currencrypt = crypt(passwordoption.c_str(),salt.c_str());		//get encrypted key
				if(strncmp(currencrypt.c_str(), actualencrypt.c_str(), currencrypt.length()) == 0){										//compare encrypoted key
					cout<<"\n\nPASSWORD FOUND: "<<passwordoption<<endl;
					cout<<"PROCESS -> "<< procid<<endl;
					return true;														//if key is found return true
				}
		
			}
			if(i==0) break;	
		}
			if(i<=1) break;
		}
			if(i<=2) break;
		}
			if(i<=3) break;
		}
			if(i<=4) break;
		}
			if(i<=5) break;
		}
			if(i<=6) break;
		}
	}
	
	return false;																		//if password is not found return false
}


//=====================================================================================================================================
//						MAIN DRIVER CODE
//=====================================================================================================================================
int main(int argc, char** argv){
	//set up MPI-----------------------------------------------------------------------------------------------------------------
	int myrank,nprocs;
	MPI_Init(&argc,&argv);
	MPI_Comm_size(MPI_COMM_WORLD,&nprocs);
	MPI_Comm_rank(MPI_COMM_WORLD,&myrank);
	
	//task division -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	int division = 8/(nprocs-1);								//task division will be done by sending each machine a range of length of passwords to search from. The ranges to send depends on number of processes(excluding master so minus 1)
	int remainder = 8%(nprocs-1);								//in case not completely divisible, alot the remainder to master node
	
	if(myrank == 0){
		cout<<"ENTER USER NAME: "<<endl;
		char user_name[50];							//get user name at run time - dynamic generic code
		cin>>user_name;
		
		//get actual encrypted password and salt to compare---------------------------------------------------------------------------
		string salt = "";
		string actualencrypt = "";
		fstream file;
		string line, filename;
		filename = "/mirror/shadow.txt";						//get actual encrypted password and its salt from shadow file
		file.open(filename.c_str(), ios::in);
		if(file.is_open()){
			while (file >> line){						//get the encrypted password of given user name from shadow file
				if (line.find(user_name) != std::string::npos){
					tokenize(line, salt, actualencrypt, "$");		//parse the information to get salt and hash
					break;						//once found username no need to look further
				}
			}
			file.close();
			//cout<<"SALT: "<<salt<<endl;
			//cout<<"HASH: "<<actualencrypt<<endl;
			if(salt == "" or actualencrypt == ""){
				cout<<"ERROR:: No user of given name could be found -- ABORT SEARCH**"<<endl;
				MPI_Abort(MPI_COMM_WORLD, 1);
				
			}
		}
		else{
			cout<<"SHADOWS FILE COULD NOT BE OPENED"<<endl;
			//in case shadow file does not open show code genericness by taking password as user input
			string actual = "aaaaabz";									//actual password
			salt = "$6$5bXhSeHX$";								//salt retreived from shadow file
			actualencrypt = crypt(actual.c_str(),salt.c_str());				//actual encrypted key
		}
		int n1 = salt.length();
		char *sendsalt;
		sendsalt = &salt[0];
		int n2 = actualencrypt.length();
		char *sendhash;
		sendhash = &actualencrypt[0];
		for(int i = 1 ; i < nprocs; i++){
			MPI_Send(&n1, 1, MPI_INT, i, 1234, MPI_COMM_WORLD);
			MPI_Send(&n2, 1, MPI_INT, i, 1234, MPI_COMM_WORLD);
			MPI_Send(sendsalt, n1, MPI_CHAR, i, 1234, MPI_COMM_WORLD);
			MPI_Send(sendhash, n2, MPI_CHAR, i, 1234, MPI_COMM_WORLD);
		}
		
		printf("MASTER: PASSWORD CHECKING HAS BEGUN\n");
		if(remainder>0){								//if max length not equalli divisible then master will search the remaining
			if(PasswordCracker(8-remainder+1,9,salt, actualencrypt, myrank) == false){
				cout<<"\nPROCESS: "<<myrank<<" -> PASSWORD WAS NOT FOUND\n"<<endl;
			}
			else{
				cout<<"***SENDING SIGNAL TO ALL PROCESSES TO ABORT SEARCH***\n";
				MPI_Abort(MPI_COMM_WORLD, 1);
			}
		}
	}
	
	//Code for slave processes to run to search for password using all possible combinations-------------------------------------------------------------------------------------------------------------
	if(myrank>0){
		char getsalt[100];
		char gethash[500];
		int saltn;
		int hashn;
		MPI_Recv(&saltn, 1, MPI_INT, 0, 1234, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
		MPI_Recv(&hashn, 1, MPI_INT, 0, 1234, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
		MPI_Recv(getsalt, 100, MPI_CHAR, 0, 1234, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
		MPI_Recv(gethash, 500, MPI_CHAR, 0, 1234, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
		string salt = convertToString(getsalt, saltn-1);
		string actualencrypt = convertToString(gethash, hashn);
		
		int start_search = 1+((myrank-1)*division);						//start for range of length assigned to each task
		int end_search = start_search+division;							//end for the range of passwords length 
		

		if(PasswordCracker(start_search,end_search,salt, actualencrypt, myrank) == false){	//run function for password search
			cout<<"\nPROCESS: "<<myrank<<" -> PASSWORD WAS NOT FOUND\n"<<endl;		//if password not found display message
		}
		else{
			cout<<"***SENDING SIGNAL TO ALL PROCESSES TO ABORT SEARCH***\n";		//if password found display message
			MPI_Abort(MPI_COMM_WORLD, 1);							//then abort all processes to stop unnecessary search
		}
	}
	

	MPI_Finalize();
}





