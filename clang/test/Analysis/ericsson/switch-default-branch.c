// RUN: %clang_analyze_cc1 -analyzer-checker=ericsson.misrac.SwitchDefaultBranch -Wno-everything -verify %s
int unusedvar=2;
void tc1(void){//This is fine default branch is there and it is final
  int c=1;
  int a=0;
  switch(c){
  case 1:
    a++;
    break;
  case 2:
    a=1;
    break;
  default:
    a=-1;
    break;
  }
}

void tc2(void){//faulty as default case is missing
  int c=1;
  int a=0;
  switch(c){// expected-warning {{The switch statement should always contain a default clause}}
  case 1:
    a++;
    break;
  case 2:
    a=1;
    break;
  }

}

void tc3(void){//Default branch is not the last, failed
  int c=1;
  int a=0;
  switch(c){// expected-warning {{In the switch statement the default branch should be the final one}}
    case 1:
    a++;
    break;
  default:
    a=-1;
    break;
  case 2:
    a=1;
    break;
  }
}

void tc4(void){//faulty as default case is missing from switch(c)
  int c=1;
  int a,b=0;
  switch(c){// expected-warning {{The switch statement should always contain a default clause}}
    case 1: {
        a++;
        switch(a){
	    case 1:
            b=2;
            break;
        default:
            b=3;
            break;
        }
        break;
    }
  case 2:
    a=1;
    break;
  }
}


void tc5(void){//faulty as default case is missing from switch(a)
  int c=1;
  int a,b=0;
  switch(c){
	case 1: {
	    a++;
	    switch(a){// expected-warning {{The switch statement should always contain a default clause}}
	    case 1:
		b=2;
		break;
	    }
	    break;
	  }
  case 2:
    a=1;
    break;
  default:
    b=3;
    break;
  }
}

int main(){
  int a=tc6(5);
  char c=tc6((char) 3);

}


