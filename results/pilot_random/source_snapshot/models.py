"""Controlled CPU baselines and DNNs with an external tuning partition."""
from copy import deepcopy
import time
import numpy as np
from sklearn.neural_network import MLPClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.dummy import DummyClassifier
from sklearn.metrics import log_loss


def fit_model(kind, x, y, x_tune, y_tune, seed, config):
    begin = time.perf_counter()
    history = []
    if kind == "dnn":
        classes = np.unique(y)
        mask = np.isin(y_tune,classes)
        if not mask.any():
            raise ValueError("No known-class tuning records")
        model = MLPClassifier(hidden_layer_sizes=tuple(config.get("hidden_layers",[64,32])),
            activation="relu", solver="adam", alpha=config.get("l2",1e-4),
            batch_size=min(len(x),config.get("batch_size",256)), learning_rate_init=config.get("learning_rate",.001),
            early_stopping=False, shuffle=True, random_state=seed, max_iter=1)
        best_loss, best_model, wait = float("inf"), None, 0
        for epoch in range(config.get("epochs",30)):
            model.partial_fit(x,y,classes=classes)
            p = model.predict_proba(x_tune[mask])
            loss = float(log_loss(y_tune[mask],p,labels=classes))
            history.append(dict(epoch=epoch+1, training_loss=float(model.loss_), tuning_log_loss=loss))
            if loss < best_loss-config.get("min_delta",1e-4):
                best_loss, best_model, wait = loss, deepcopy(model), 0
            else:
                wait += 1
            if wait >= config.get("patience",5):
                break
        model = best_model
    elif kind == "random_forest":
        model = RandomForestClassifier(n_estimators=config.get("trees",100),
            min_samples_leaf=2,max_features="sqrt",class_weight=None,random_state=seed,n_jobs=1).fit(x,y)
    elif kind == "logistic":
        model = LogisticRegression(max_iter=config.get("logistic_iterations",500),C=1,random_state=seed).fit(x,y)
    elif kind == "dummy":
        model = DummyClassifier(strategy="prior").fit(x,y)
    else:
        raise ValueError("Unknown model: " + kind)
    return model, dict(seconds=time.perf_counter()-begin,history=history,
        best_epoch=min(history,key=lambda r:r["tuning_log_loss"])["epoch"] if history else None,
        tuning_unknown_rows=int((~np.isin(y_tune,np.unique(y))).sum()))


class BinaryCalibrator:
    """Platt calibration on the dedicated natural-prevalence calibration split."""
    @staticmethod
    def design(p):
        p = np.clip(np.asarray(p,dtype=float),1e-6,1-1e-6)
        return np.log(p/(1-p)).reshape(-1,1)

    def fit(self,p,y):
        if np.unique(y).size != 2:
            raise ValueError("Calibration requires benign and attack records")
        self.model_ = LogisticRegression(C=1,solver="lbfgs",max_iter=1000).fit(self.design(p),y)
        return self

    def predict(self,p):
        return self.model_.predict_proba(self.design(p))[:,list(self.model_.classes_).index(True)]
