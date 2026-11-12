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
        best_loss, best_model, wait, retained_epoch = float("inf"), None, 0, None
        for epoch in range(config.get("epochs",30)):
            model.partial_fit(x,y,classes=classes)
            p = model.predict_proba(x_tune[mask])
            loss = float(log_loss(y_tune[mask],p,labels=classes))
            history.append(dict(epoch=epoch+1, training_loss=float(model.loss_), tuning_log_loss=loss))
            if loss < best_loss-config.get("min_delta",1e-4):
                best_loss, best_model, wait = loss, deepcopy(model), 0
                retained_epoch=epoch+1
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
        best_epoch=retained_epoch if history else None,
        minimum_loss_epoch=min(history,key=lambda r:r["tuning_log_loss"])["epoch"] if history else None,
        tuning_unknown_rows=int((~np.isin(y_tune,np.unique(y))).sum()))


class BinaryCalibrator:
    """Monotonic Platt calibration on the dedicated calibration split."""
    def __init__(self,method="monotonic"):
        if method not in {"identity","monotonic","unrestricted"}:
            raise ValueError("Unknown calibration method")
        self.method_=method

    @staticmethod
    def design(p):
        p = np.clip(np.asarray(p,dtype=float),1e-6,1-1e-6)
        return np.log(p/(1-p)).reshape(-1,1)

    def fit(self,p,y,min_per_class=1,fallback="none"):
        if np.unique(y).size != 2:
            raise ValueError("Calibration requires benign and attack records")
        self.requested_method_=self.method_
        self.attack_support_=int(np.asarray(y,dtype=bool).sum())
        self.benign_support_=len(y)-self.attack_support_
        self.fallback_reason_=None
        if self.method_!="identity" and min(self.attack_support_,self.benign_support_)<min_per_class:
            self.fallback_reason_=f"calibration support below {min_per_class} per class"
            if fallback=="error":raise ValueError(self.fallback_reason_)
            if fallback=="identity":self.method_="identity"
        if self.method_=="identity":
            return self
        if self.method_=="unrestricted":
            self.model_ = LogisticRegression(C=1,solver="lbfgs",max_iter=1000).fit(self.design(p),y)
        else:
            from scipy.optimize import minimize
            from scipy.special import expit
            x=self.design(p).ravel()
            target=np.asarray(y,dtype=float)
            prevalence=np.clip(target.mean(),1e-6,1-1e-6)
            def objective(params):
                a,b=params
                z=a*x+b
                error=expit(z)-target
                # Match a weak L2 penalty on slope, never on the intercept.
                penalty=a*a/(2*len(x))
                loss=float(np.mean(np.logaddexp(0,z)-target*z)+penalty)
                gradient=np.array([np.mean(error*x)+a/len(x),np.mean(error)])
                return loss,gradient
            fitted=minimize(objective,[1.,np.log(prevalence/(1-prevalence))],jac=True,
                bounds=[(1e-4,100.),(-50.,50.)],method="L-BFGS-B",options={"maxiter":1000})
            if not fitted.success:
                raise ValueError("Monotonic calibration optimization failed: "+fitted.message)
            self.slope_,self.intercept_=map(float,fitted.x)
            self.boundary_solution_=self.slope_<=1.01e-4
            if self.boundary_solution_ and fallback!="none":
                self.fallback_reason_="monotonic slope reached lower bound"
                if fallback=="error":raise ValueError(self.fallback_reason_)
                self.method_="identity"
        return self

    def predict(self,p):
        if getattr(self,"method_",None)=="identity":
            return np.asarray(p,dtype=float).copy()
        if getattr(self,"method_","unrestricted")=="unrestricted":
            return self.model_.predict_proba(self.design(p))[:,list(self.model_.classes_).index(True)]
        from scipy.special import expit
        return expit(self.slope_*self.design(p).ravel()+self.intercept_)
