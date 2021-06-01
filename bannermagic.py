import os
from enum import Enum

class Location(Enum):
	left=1
	right=2
	center=3

columns = os.get_terminal_size()[0]

# print the banner beauty
def printBannerPadding(char='='):
	print(char*columns)

# print the message inside the banner on the center
def printMessage(message, location=Location.center):
	# Calculate how many spaces we want for padding

	if location == Location.left:
		spaces = 0
	elif location == Location.right:
		spaces = columns - len(message)
	else:
		spaces = (columns - len(message)) //2

	if spaces < 0:
		spaces = 0

	print(' '*spaces + message)


if __name__ == '__main__':
	printBannerPadding('*')
	printMessage('Hello i am centered!')
	printMessage('Hello i am on the left!', location=Location.left)
	printMessage('Hello i am on the right!', location=Location.right)
	printBannerPadding('*')