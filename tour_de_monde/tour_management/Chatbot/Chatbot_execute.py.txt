import re #regular expression operations
import random #generate pseudo random numbers
import numpy as np #array operations
from nltk.tokenize import word_tokenize #tokenizer -> converts string to tokens
from keras.callbacks import History
import matplotlib.pyplot as plt
import tensorflow as tf
# modules needed for building seq2seq model
from tensorflow import keras # Keras is an open-source library that provides a Python interface for artificial neural networks.
from keras.layers import Input # Layer to be used as an entry point into a Network (a graph of layers).
from keras.layers import LSTM # Long Short-Term Memory layer
from keras.layers import Dense # regular densely-connected NN layer.
from keras.models import Model # Model groups layers into an object with training and inference features.
from keras.models import load_model # Loads a model saved via model.save()

Train_model = load_model('Train_model.h5')
EncoderInput = Train_model.input[0]
EncoderOutput,state_h_En,state_c_En = Train_model.layers[2].output
EncoderStates = [state_h_En, state_c_En]
EncoderModel = Model(EncoderInput,EncoderStates)

latent_dim = 512
DecoderStateInput_hid = Input(shape=(latent_dim,))
DecoderStateInput_cell = Input(shape=(latent_dim,))
DecoderStateInput = [DecoderStateInput_hid,DecoderStateInput_cell]

DecoderOutput,HiddenState_En,StateCell_En = DecoderLSTM(DecoderInput,initial_state=DecoderStateInput)
DecoderState = [HiddenState_En,StateCell_En]
DecoderOutput = DecoderDense(DecoderOutput)

DecoderModel = Model([DecoderInput] + DecoderStateInput,[DecoderOutput] + DecoderState)


negative_word = ("no", "nope", "nah", "naw", "not a chance", "sorry", "never") # list of negative responses
exit_word = ("quit", "pause", "exit", "goodbye", "bye", "later", "stop") # list of exit cues
exclamation_word = ("okay","thanks","thank you","okay nice","okay nice to know","nice") # list of exclamatory responses

#Method to check for exit commands
def ExitFunc(r):
    for e in exit_word:
        if e in r:
            a=1
            print("okay , have a great day")
            return True
    return False                  
    
#Method to check for exclamation
def ExclamationFunc(r):
    for e in exclamation_word:
        if e in r:
            print("okay , happy to help")
            return True
    return False
a=0
while a==0:
    user_input = input("Hi, I'm Kolly. I can help you with Kolkata tourism. Ask me about historical locations & restaurants. Type `bye` to exit me. What would you like to know?\n")
    if user_input in negative_word:
        print("okay , have a great day")
        break
    else:
        if ExitFunc(user_input):
            a=1
            break
        while not ExitFunc(user_input): #ExitFunc returns if user_input contains exit cue
            if ExclamationFunc(user_input): #ExclamationFunc returns if user_input contains exclamation word
                user_input = input()
            else:#generate answer and take new input
                ans="" #stores final answer to be shown
                match_found=0
                for x in lis:#looping to find if a perfect match for user query exists in database
                    if(user_input.lower() == x[0]):#perfect match
                        ans=str(x[1])
                        match_found=1
                if(match_found == 1):
                    user_input = input(ans+"\n")#final answer is shown and a new user input is taken
                else:
                    t = word_tokenize(user_input.lower())
                    M = np.zeros((1,MaxEncoder_Len,EncoderTokenLen),dtype='float32')
                    for ts,x in enumerate(t):
                        if x in InputFeatures_Dict:
                            M[0,ts,InputFeatures_Dict[x]] = 1.0

                    #Decode answer
                    #Getting the output states to pass into the decoder
                    StateValue = EncoderModel.predict(M)
                    #Generating empty target sequence of length 1
                    OutputSequence = np.zeros((1,1,DecoderTokenLen))
                    #Setting the first token of target sequence with the start token
                    OutputSequence[0,0,OutputFeatures_Dict['START']] = 1.0
                    flag = 1
                    while(flag == 1):
                        #Predicting output tokens with probabilities and states
                        OutputTokens,HiddenState,CellState = DecoderModel.predict([OutputSequence]+StateValue)
                        #Choosing the one with highest probability
                        i = np.argmax(OutputTokens[0, -1, :])
                        t = RevOutputFeatures_Dict[i]
                        ans = ans + " " + t
                        #Stop if found the stop token
                        if(t == 'STOP'):
                            flag = 0
                        OutputSequence = np.zeros((1, 1, DecoderTokenLen))
                        OutputSequence[0,0,i] = 1.0
                        #Update states
                        StateValue=[HiddenState,CellState]
                        #Remove <START> and <STOP> tokens from chatbot_response
                        ans = ans.replace("START",'')
                        ans = ans.replace("STOP",'')
                    user_input = input(ans+"\n")#final answer is shown and a new user input is taken


