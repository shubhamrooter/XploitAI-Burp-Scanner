try:
    import cPickle as pickle
except ImportError:
    import pickle

class AIModel:
    def __init__(self, model_path):
        try:
            with open(model_path, "rb") as f:
                self.model = pickle.load(f)
        except Exception as e:
            raise Exception("Error loading AI model: {}".format(str(e)))

    def predict(self, input_data):
        try:
            prediction = self.model.predict([input_data])
            return prediction
        except Exception as e:
            raise Exception("Error making prediction: {}".format(str(e)))