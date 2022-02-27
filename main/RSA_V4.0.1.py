from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox
from base64 import b64encode, b64decode
import hashlib
import os
import random
import pathlib
import sqlite3
from math import gcd
from ttkthemes import ThemedTk
import time
import ctypes
import hashlib
ctypes.windll.shcore.SetProcessDpiAwareness(1)


class database_manager:
    def __init__(self):
        self.con = sqlite3.connect('RSA_CRYPTO.db')
        self.cur = self.con.cursor()
        self.cur.execute(
            "CREATE TABLE IF NOT EXISTS connexion(utilisateur VARCHAR PRIMARY KEY, mot_de_passe VARCHAR)")
        self.cur.execute(
            "CREATE TABLE IF NOT EXISTS donnees_cryptage(utilisateur VARCHAR,date DATE,fichier,dictionnaire de cles,FOREIGN KEY (utilisateur) REFERENCES connexion(utilisateur))")
        self.con.commit()

    def partie_objet_tableau(self, nom_tableau, user='', colonne=0):
        if nom_tableau == 'connexion':
            self.cur.execute(f'SELECT * FROM {nom_tableau}')
        elif nom_tableau == 'donnees_cryptage':
            self.cur.execute(
                f'SELECT * FROM {nom_tableau} WHERE utilisateur = (?)', (user,))
        donnees = self.cur.fetchall()
        self.con.commit()
        colonne_tuple = ()
        for donnee in donnees:
            colonne_tuple += (donnee[colonne],)
        return (colonne_tuple, donnees)

    def trouver_objet(self, nom_tableau, objet, colonne):
        self.cur.execute(
            f'SELECT * FROM {nom_tableau} WHERE "{colonne}" = (?)', (objet,))
        donnees = self.cur.fetchall()
        self.cur.commit()
        if donnees != []:
            return True
        return False

    def ajouter_objet(self, nom_tableau, objet):
        if nom_tableau == 'connexion':

            self.cur.execute(f'INSERT INTO {nom_tableau} VALUES(?,?)', objet)
            self.con.commit()
        elif nom_tableau == 'donnees_cryptage':

            self.cur.execute(
                f'INSERT INTO {nom_tableau} VALUES(?,?,?,?)', objet)
            self.con.commit()

    def supprimer_objet(self, nom_tableau, colonne, objet):
        self.cur.execute(
            f'DELETE FROM {nom_tableau} WHERE {colonne} = (?)', (objet,))
        self.con.commit()


class MainWindow(ThemedTk):
    def __init__(self, bd):
        ThemedTk.__init__(self, theme="arc")
        self.bd = bd

        self.mainWidgets()

    def mainWidgets(self):
        self.title('RSA Crypto')
        self.iconbitmap(self, 'RSA_CRYPTO_inicon.ico')
        x = self.winfo_screenwidth()//2 - 400//2
        y = self.winfo_screenheight()//2 - 500//2
        self.geometry(f'400x500+{x}+{y}')
        self.resizable(0, 0)
        self.configure(bg='#FFFFFF')
        self.fenetre = fenetre1(self, self.bd)


class fenetre1(Frame):
    def __init__(self, parent, bd):
        Frame.__init__(self, parent, bg='#FFFFFF')
        self.place(relx=0.5, rely=0.5, anchor=CENTER)
        self.parent = parent
        self.mainWidgets()

    def mainWidgets(self):
        # insertion de l'image d'entree---------------------------------------------------------------------------------------------------
        self.img = PhotoImage(file=r"RSA_CRYPTO_home.png")
        self.photo = Label(self, image=self.img, bg='#FFFFFF')
        # Partie de nom d'utilisateur-----------------------------------------------------------------------------------------------------
        self.utilisateur_lb = Label(
            self, text='Utilisateur', bg='#FFFFFF', font=('arial', 10, 'bold'))
        self.utilisateur = StringVar()
        self.utilisateur_en = ttk.Combobox(self, values=bd.partie_objet_tableau(
            'connexion')[0], textvariable=self.utilisateur)
        # Partie de mot de passe----------------------------------------------------------------------------------------------------------
        self.mot_de_passe = StringVar()
        self.mot_de_passe_lb = Label(
            self, text='Mot de passe', bg='#FFFFFF', font=('arial', 10, 'bold'))
        self.mot_de_passe_en = ttk.Entry(
            self, show='*', textvariable=self.mot_de_passe)
        # partie bouton de connection-----------------------------------------------------------------------------------------------------
        self.se_connecter_btn = ttk.Button(
            self, text='Se connecter', command=self.se_connecter)
        self.inscrire_btn = ttk.Button(
            self, text="S'inscrire", command=self.inscrire)
        self.supprimer_btn = ttk.Button(
            self, text="Supprimer compte", command=self.supprimer)
        # Creation des extentions---------------------------------------------------------------------------------------------------------
        self.photo.grid(row=0, column=1, columnspan=2, pady=5)
        self.utilisateur_lb.grid(row=1, column=1, columnspan=2, pady=5)
        self.utilisateur_en.grid(row=2, column=1, columnspan=2, pady=5)
        self.mot_de_passe_lb.grid(row=3, column=1, columnspan=2, pady=5)
        self.mot_de_passe_en.grid(row=4, column=1, columnspan=2, pady=5)
        self.se_connecter_btn.grid(row=5, column=1, columnspan=2, pady=5)
        self.inscrire_btn.grid(row=6, column=1, columnspan=2, pady=5)
        self.supprimer_btn.grid(row=7, column=1, columnspan=2, pady=5)
        # --------------------------------------------------------------------------------------------------------------------------------
        # --------------------------------------------------------------------------------------------------------------------------------
    #################################################################################################################################
    #-------------------------------------------------------Fonction Predefinie-----------------------------------------------------#
    #################################################################################################################################

    def clear_frame(self):

        for widgets in self.winfo_children():

            widgets.destroy()
    # se connecter au compte choisie--------------------------------------------------------------------------------------------------

    def se_connecter(self):

        if self.utilisateur_en.get() == '' or self.mot_de_passe_en.get() == '':
            messagebox.showerror('Alert', 'Champs vides !!')

        else:

            for donnee in bd.partie_objet_tableau('connexion')[1]:

                if self.utilisateur_en.get() == donnee[0] and hashlib.md5(self.mot_de_passe_en.get().encode()).hexdigest() == donnee[1]:
                    user = self.utilisateur.get()

                    self.utilisateur.set('')
                    self.mot_de_passe.set('')
                    test = messagebox.askokcancel(
                        'Information', 'Voulez vous continuer?')
                    if test == True:
                        self.clear_frame()
                        self.fenetre_cryptage = fenetre3(
                            self.parent, bd, user, self.mot_de_passe.get())
                        self.fenetre_cryptage.mainloop()
                        break
                    else:
                        break

            else:
                messagebox.showerror(
                    'Alert', "Nom d'utilisateur ou mot de passe est incorrect")

    # --------------------------------------------------------------------------------------------------------------------------------
    # se connecter au compte choisie--------------------------------------------------------------------------------------------------
    def inscrire(self):
        self.clear_frame()
        self.fenetre_inscription = fenetre2(self.parent, bd)
        self.fenetre_inscription.mainloop()

    def supprimer(self):

        if self.utilisateur_en.get() == '' or self.mot_de_passe_en.get() == '':
            messagebox.showerror('Alert', 'Champs vides !!')

        else:

            for donnee in bd.partie_objet_tableau('connexion')[1]:

                if self.utilisateur_en.get() == donnee[0] and hashlib.md5(self.mot_de_passe_en.get().encode()).hexdigest() == donnee[1]:
                    test = messagebox.askokcancel(
                        'Alert', 'La suppression est definitive \nVoulez vous continuer?')
                    if test == True:
                        bd.supprimer_objet(
                            'connexion', 'utilisateur', self.utilisateur_en.get())

                        bd.supprimer_objet(
                            'donnees_cryptage', 'utilisateur', self.utilisateur_en.get())
                        self.clear_frame()
                        self.fenetre_connexion = fenetre1(self.parent, bd)
                        self.fenetre_connexion.mainloop()

                    break

            else:
                messagebox.showerror(
                    'Alert', "Nom d'utilisateur ou mot de passe est incorrect")

            # --------------------------------------------------------------------------------------------------------------------------------


class fenetre2(Frame):
    def __init__(self, parent, bd):
        Frame.__init__(self, parent, bg='#FFFFFF')
        self.place(relx=0.5, rely=0.5, anchor=CENTER)
        self.parent = parent
        self.mainWidgets()

    def mainWidgets(self):
        # Partie de nom d'utilisateur-----------------------------------------------------------------------------------------------------
        self.utilisateur_ins_lb = Label(
            self, text='Utilisateur', bg='#FFFFFF', font=('arial', 10, 'bold'))
        self.utilisateur_ins = StringVar()
        self.utilisateur_ins_en = ttk.Entry(
            self, textvariable=self.utilisateur_ins)
        # Partie de mot de passe----------------------------------------------------------------------------------------------------------
        self.mot_de_passe_ins = StringVar()
        self.mot_de_passe_ins_lb = Label(
            self, text='Mot de passe', bg='#FFFFFF', font=('arial', 10, 'bold'))
        self.mot_de_passe_ins_en = ttk.Entry(
            self, show='*', textvariable=self.mot_de_passe_ins)
        self.conf_mot_de_passe_ins = StringVar()
        self.conf_mot_de_passe_lb = Label(
            self, text='Confirmer mot de passe', bg='#FFFFFF', font=('arial', 10, 'bold'))
        self.conf_mot_de_passe_en = ttk.Entry(
            self, show='*', textvariable=self.conf_mot_de_passe_ins)
        # partie bouton de connection-----------------------------------------------------------------------------------------------------
        self.valider_inscription_btn = ttk.Button(
            self, text='Valider', command=self.valider)
        self.retour_btn = ttk.Button(self, text="Retour", command=self.retour)
        # Creation des extentions---------------------------------------------------------------------------------------------------------
        self.utilisateur_ins_lb.grid(row=1, column=1, columnspan=2, pady=5)
        self.utilisateur_ins_en.grid(row=2, column=1, columnspan=2, pady=5)
        self.mot_de_passe_ins_lb.grid(row=3, column=1, columnspan=2, pady=5)
        self.mot_de_passe_ins_en.grid(row=4, column=1, columnspan=2, pady=5)
        self.conf_mot_de_passe_lb.grid(row=5, column=1, columnspan=2, pady=5)
        self.conf_mot_de_passe_en.grid(row=6, column=1, columnspan=2, pady=5)
        self.valider_inscription_btn.grid(
            row=7, column=1, columnspan=2, pady=5)
        self.retour_btn.grid(row=8, column=1, columnspan=2, pady=5)
        # --------------------------------------------------------------------------------------------------------------------------------
    #################################################################################################################################
    #-------------------------------------------------------Fonction Predefinie-----------------------------------------------------#
    #################################################################################################################################

    def clear_frame(self):

        for widgets in self.winfo_children():

            widgets.destroy()

    def valider(self):

        if self.utilisateur_ins_en.get() != '' and self.mot_de_passe_ins_en.get() != '' and self.conf_mot_de_passe_en.get() != '':
            colonne_tuple = bd.partie_objet_tableau('connexion')[0]

            for user in colonne_tuple:

                if self.utilisateur_ins_en.get() == user:
                    self.utilisateur_ins.set('')
                    self.mot_de_passe_ins.set('')
                    self.conf_mot_de_passe_ins.set('')

                    return messagebox.showerror('Alert', 'Ce utilisateur existe deja')
            if self.mot_de_passe_ins_en.get() != self.conf_mot_de_passe_en.get():
                self.mot_de_passe_ins.set('')
                self.conf_mot_de_passe_ins.set('')

                messagebox.showerror(
                    'Alert', 'Les mots de passes sont differents')
            elif len(self.mot_de_passe_ins_en.get()) < 8:
                self.mot_de_passe_ins.set('')
                self.conf_mot_de_passe_ins.set('')
                messagebox.showerror(
                    'Alert', 'Mot de passe est faible \n veuiller depasser 8 caracteres')

            else:
                test = messagebox.askokcancel(
                    'Information', 'Voulez vous continuer?')
                if test == True:
                    mot_de_passe_securiser = hashlib.md5(
                        self.mot_de_passe_ins_en.get().encode()).hexdigest()
                    bd.ajouter_objet(
                        'connexion', (self.utilisateur_ins_en.get(), mot_de_passe_securiser))
                    self.clear_frame()

                    self.fenetre_de_connection = fenetre1(self.parent, bd)
                    self.fenetre_de_connection.mainloop()

        else:
            messagebox.showerror('Alert', 'Champs vides !!')

    def retour(self):

        self.clear_frame()

        self.fenetre_de_connection = fenetre1(self.parent, bd)
        self.fenetre_de_connection.mainloop()
# --------------------------------------------------------------------------------------------------------------------------------


class fenetre3(Frame):
    def __init__(self, parent, bd, user, password):
        Frame.__init__(self, parent, bg='#FFFFFF')
        self.place(relx=0.5, rely=0.5, anchor=CENTER)
        self.parent = parent
        self.user = user
        self.password = password
        self.chemainStr = ''
        self.mainWidgets()

    def mainWidgets(self):
        # insertion du fichier de cryptage -----------------------------------------------------------------------------------------------
        self.inserer_lb = Label(
            self, text='Inserer Fichier', bg='#FFFFFF', font=('arial', 10, 'bold'))
        self.chemain = StringVar()
        self.inserer_en = ttk.Entry(self, textvariable=self.chemain)
        self.ouvrir_btn = ttk.Button(
            self, text='Ouvrir', command=self.fileINopen)
        # Choix entre cryptage ou decryptage ---------------------------------------------------------------------------------------------
        self.choix = StringVar()
        s = ttk.Style()

        s.configure('white.TRadiobutton', background="#FFFFFF")
        self.choix1 = ttk.Radiobutton(self, text='Crypter', value='crypter',
                                      variable=self.choix, style='white.TRadiobutton', command=self.click_rbtn)
        self.choix2 = ttk.Radiobutton(self, text='Decrypter', value='decrypter',
                                      variable=self.choix, style='white.TRadiobutton', command=self.click_rbtn)
        # Choix de cle de cryptage -------------------------------------------------------------------------------------------------------
        self.cle = StringVar()
        valeurs = bd.partie_objet_tableau('donnees_cryptage', self.user, 2)[0]
        vals = ()
        for i in range(len(valeurs)):
            vals += (str(i+1)+'-'+valeurs[i],)
        self.cle_privee = ttk.Combobox(
            self, values=vals, textvariable=self.cle, state='disable')
        # Traitement du self.choix-------------------------------------------------------------------------------------------------------------
        self.executer_btn = ttk.Button(
            self, text='Executer', command=self.executer, state='disable')
        # Affichange de l'historique
        self.historique_btn = ttk.Button(
            self, text='historique', command=self.historique)
        # Se deconnecter
        self.se_deconnecter_btn = ttk.Button(
            self, text='Se deconnecter', command=self.se_deconnecter)
        # Creation des extentions---------------------------------------------------------------------------------------------------------
        self.historique_btn.grid(row=6, column=0, columnspan=2, pady=5)
        self.se_deconnecter_btn.grid(row=6, column=2, columnspan=2, pady=5)
        self.inserer_lb.grid(row=0, column=1, columnspan=2, pady=5)
        self.inserer_en.grid(row=1, column=1, columnspan=2, pady=5)
        self.ouvrir_btn.grid(row=2, column=1, columnspan=2, pady=5)
        self.choix1.grid(row=3, column=1, pady=20, padx=5)
        self.choix2.grid(row=3, column=2, pady=20, padx=5)
        self.cle_privee.grid(row=4, column=1, columnspan=2, pady=5)
        self.executer_btn.grid(row=5, column=1, columnspan=2, pady=5)
        # --------------------------------------------------------------------------------------------------------------------------------
    #################################################################################################################################
    #-------------------------------------------------------Fonction Predefinie-----------------------------------------------------#
    #################################################################################################################################
    # l'insertion du fichier pour le crypter-----------------------------------------------------------------------------------------

    def clear_frame(self):

        for widgets in self.winfo_children():

            widgets.destroy()

    def fileINopen(self):
        self.chemainStr = filedialog.askopenfilename()
        filename = self.chemainStr.split('/')[-1]
        self.chemain.set(filename)
        return self.chemainStr

    # --------------------------------------------------------------------------------------------------------------------------------
    def historique(self):
        self.fenetre_historique = fenetre4(
            self, self.parent, bd, self.user, self.password)
        self.fenetre_historique.mainloop()
    # None----------------------------------------------------------------------------------------------------------------------------

    def executer(self):
        if self.chemain.get() != '':
            if self.choix.get() == 'crypter':
                date = time.strftime("%D-%H:%M:%S", time.localtime())

                def est_premier(num):
                    if num == 2:
                        return True
                    if num < 2 or num % 2 == 0:
                        return False
                    for n in range(3, int(num**0.5)+2, 2):
                        if num % n == 0:
                            return False
                    return True

                def generateurDesCles():
                    p = generateurDesNbrPremier()
                    q = generateurDesNbrPremier()
                    n = p*q
                    phi = (p-1) * (q-1)
                    e = random.randint(1, phi)
                    g = gcd(e, phi)
                    while g != 1:
                        e = random.randint(1, phi)
                        g = gcd(e, phi)
                    d = egcd(e, phi)[1]
                    d = d % phi
                    if(d < 0):
                        d += phi

                    return ((e, n), (d, n))

                def generateurDesNbrPremier(keysize=1000):
                    while True:
                        ranPremier = random.randint(50, keysize)
                        if est_premier(ranPremier):
                            return ranPremier

                def egcd(a, b):
                    s = 0
                    old_s = 1
                    t = 1
                    old_t = 0
                    r = b
                    old_r = a
                    while r != 0:
                        quotient = old_r // r
                        old_r, r = r, old_r - quotient * r
                        old_s, s = s, old_s - quotient * s
                        old_t, t = t, old_t - quotient * t
                    # return gcd, x, y
                    return old_r, old_s, old_t

                def cryptage(public_key, msg):
                    key, n = public_key
                    cipher = ""
                    for c in msg:
                        m = ord(c)
                        cipher += str(pow(m, key, n)) + " "
                    return cipher
                public_key, private_key = generateurDesCles()
                try:

                    fI = open(self.chemainStr, 'rb')

                    msg = fI.read()
                    ctext = cryptage(public_key, msg.decode("ansi"))
                    extention = self.chemain.get().split('.')[-1]
                    data = [(f'*.{extention}', f'*.{extention}')]
                    chemin = filedialog.asksaveasfilename(
                        confirmoverwrite=False, filetypes=data, defaultextension=data)
                    fO = open(chemin, 'wb')
                    fO.write(ctext.encode("ansi"))
                    fO.close()
                    fI.close()
                    private_key = bdcrypto(
                        self.password, str(private_key)).encrypt()
                    bd.ajouter_objet(
                        'donnees_cryptage', (self.user, date, self.chemain.get(), str(private_key)))
                    messagebox.showinfo(
                        'info', 'Le cryptage est termine <^_^>')

                    self.clear_frame()
                    self.fenetre_cryptage = fenetre3(
                        self.parent, bd, self.user, self.password)
                    self.fenetre_cryptage.mainloop()
                except Exception as e:
                    messagebox.showerror('info', e)
            elif self.choix.get() == 'decrypter':
                if self.cle_privee.get() == '':
                    messagebox.showerror('Alert', 'Champs vides!!')
                else:
                    test = False
                    valeurs = bd.partie_objet_tableau(
                        'donnees_cryptage', self.user, 2)[0]
                    for i in range(len(valeurs)):
                        if (str(i+1)+'-'+valeurs[i]) == self.cle_privee.get():
                            test = True
                            break
                    if test == True:
                        index = int(self.cle_privee.get()[0])
                        val = eval(bd.partie_objet_tableau(
                            'donnees_cryptage', self.user, 3)[0][index-1])
                        private_key = eval(
                            bdcrypto(self.password, '', val).decrypt())

                        def decryptage(private_key, cipher):
                            key, n = private_key
                            msg = ""
                            parts = cipher.split()
                            for part in parts:
                                if part:
                                    c = int(part)
                                    msg += chr(pow(c, key, n))
                            return msg
                        try:
                            fI = open(self.chemainStr, 'rb')
                            msg = fI.read()
                            text = decryptage(private_key, msg.decode("ansi"))
                            extention = self.chemain.get().split('.')[-1]
                            data = [(f'*.{extention}', f'*.{extention}')]
                            chemin = filedialog.asksaveasfilename(
                                confirmoverwrite=False, filetypes=data, defaultextension=data)
                            fO = open(chemin, 'wb')
                            text = text.encode("ansi")
                            fO.write(text)
                            fO.close()
                            fI.close()
                            messagebox.showinfo(
                                'info', 'Le decryptage est termine <^_^>')
                            self.clear_frame()
                            self.fenetre_cryptage = fenetre3(
                                self.parent, bd, self.user, self.password)
                            self.fenetre_cryptage.mainloop()
                        except Exception as e:
                            messagebox.showerror('info', e)
                    else:
                        messagebox.showerror(
                            'Alert', 'Cle privee est imcompatible!')

        else:
            messagebox.showerror('Alert', 'Champs vides!!')

    # --------------------------------------------------------------------------------------------------------------------------------
    # Activation et desactivation de la partie de la selection des cles---------------------------------------------------------------

    def click_rbtn(self):

        test = self.choix.get()

        self.executer_btn.config(state='normale')

        if test == 'crypter':
            self.cle_privee.config(state='disable')
        elif test == 'decrypter':
            self.cle_privee.config(state='normal')
    # -------------------------------------------------------------------------------------------------------------------------------
    # --------------------------------------------------------------------------------------------------------------------------------
    # commande de deconnection et l'affiche de la partie connection-------------------------------------------------------------------

    def se_deconnecter(self):
        self.clear_frame()
        self.fenetre_de_connection = fenetre1(self.parent, bd)
        self.fenetre_de_connection.mainloop()
    # --------------------------------------------------------------------------------------------------------------------------------


class fenetre4(Toplevel):
    def __init__(self, manager, parent, bd, user, password):
        Toplevel.__init__(self, parent, bg='#FFFFFF')
        self.grab_set()
        self.parent = parent
        self.manager = manager
        self.password = password
        self.user = user
        self.mainWidgets()

    def mainWidgets(self):
        self.title('Historique de cryptage')
        x = self.winfo_screenwidth()//2 - 900//2
        y = self.winfo_screenheight()//2 - 400//2
        self.geometry(f'+{x}+{y}')
        self.resizable(0, 0)
        # Titre du self.tableau---------------------------------------------------------------------------------------------------------------
        self.historique_lb = Label(self, bg="white", text='Historique')
        self.historique_lb.grid(row=0, column=4, padx=(0, 10), pady=(5, 0))
        # construction du self.tableau d'historique--------------------------------------------------------------------------------------------
        self.tableau = ttk.Treeview(self, columns=('date', 'fichier'))
        self.tableau.heading('date', text='Date')
        self.tableau.heading('fichier', text='Fichier')
        # sans ceci, il y avait une colonne vide à gauche qui a pour rôle d'afficher le paramètre "text" qui peut être spécifié lors du insert
        self.tableau['show'] = 'headings'
        self.sbar = ttk.Scrollbar(
            self, orient="vertical", command=self.tableau.yview)
        self.tableau.grid(row=1, column=1, columnspan=6, padx=(
            5, 0), pady=(5, 0), sticky="news", rowspan=5)

        self.sbar.grid(row=1, column=7, rowspan=5, pady=(5, 0), sticky='ns')
        self.tableau.configure(yscrollcommand=self.sbar.set)
        # bouton pour fermer la self.fenetre_historique-------------------------------------------------------------------------------------------------
        self.fermer_btn = ttk.Button(self, text='Fermer', command=self.destroy)
        self.supprimer_btn = ttk.Button(
            self, text='Supprimer', command=self.supprimer_element)
        self.fermer_btn.grid(row=6, column=1, pady=5)
        self.supprimer_btn.grid(row=6, column=6, pady=5)
        donnees = bd.partie_objet_tableau('donnees_cryptage', self.user)[1]
        for donnee in donnees:

            self.tableau.insert(
                '', 'end', iid=donnee[1], values=(donnee[1], donnee[2]))

    def supprimer_element(self):
        selected_items = self.tableau.selection()
        if selected_items != ():
            test = messagebox.askokcancel(
                'Alert', 'La suppression est definitive \nVoulez vous continuer?')
            if test == True:
                for element_selectionnee in selected_items:
                    bd.supprimer_objet('donnees_cryptage',
                                       'date', element_selectionnee)
                    self.tableau.delete(element_selectionnee)
                    self.manager.destroy()
                    self.fenetre3 = fenetre3(
                        self.parent, bd, self.user, self.password)
        else:
            messagebox.showerror(
                'Erreur', 'Vous devez selectionner un element')


class bdcrypto():
    def __init__(self, password, texte='', enc_dict={}):

        self.password = password
        self.texte = texte
        self.enc_dict = enc_dict

    def encrypt(self):
        salt = get_random_bytes(AES.block_size)
        private_key = hashlib.scrypt(
            self.password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
        cipher_config = AES.new(private_key, AES.MODE_GCM)
        cipher_text, tag = cipher_config.encrypt_and_digest(
            bytes(self.texte, 'utf-8'))

        return {
            'cipher_text': b64encode(cipher_text).decode('utf-8'),
            'salt': b64encode(salt).decode('utf-8'),
            'nonce': b64encode(cipher_config.nonce).decode('utf-8'),
            'tag': b64encode(tag).decode('utf-8')
        }

    def decrypt(self):
        # decode the dictionary entries from base64
        salt = b64decode(self.enc_dict['salt'])
        cipher_text = b64decode(self.enc_dict['cipher_text'])
        nonce = b64decode(self.enc_dict['nonce'])
        tag = b64decode(self.enc_dict['tag'])
        # generate the private key from the password and salt
        private_key = hashlib.scrypt(
            self.password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
        # create the cipher config
        cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)
        # decrypt the cipher text
        decrypted = cipher.decrypt_and_verify(cipher_text, tag)
        return decrypted.decode()

        # -------------------------------------------------------------------------------------------------------------------------------
        # --------------------------------------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    bd = database_manager()
    w = MainWindow(bd)
    w.mainloop()
