import pickle

from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier


class ModelManager:

    @staticmethod
    def get_model(model_name):
        path_to_model = f'trained_models/{model_name}.sav'
        return pickle.load(open(path_to_model, 'rb'))

    @staticmethod
    def save_model(model, model_name):
        path_to_save = f'trained_models/{model_name}.sav'
        pickle.dump(model, open(path_to_save, 'wb'))

    def retrain_model(self, model_name, train_data, train_results):
        model = None
        match model_name:
            case 'knn':
                model = KNeighborsClassifier()
            case 'logistic_regression':
                model = LogisticRegression()
            case 'decision_tree':
                model = DecisionTreeClassifier()
        model.fit(train_data, train_results)
        self.save_model(model, model_name)

    def incremental_train_model(self):
        pass
