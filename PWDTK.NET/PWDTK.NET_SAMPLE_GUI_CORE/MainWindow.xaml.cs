using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using PWDTK_DOTNET;

namespace PWDTK_SAMPLE_GUI_CORE
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private Byte[] _salt;
        private Byte[] _hash;

        //Below is used to generate a password policy that you may use to check that passwords adhere to this policy
        private const int numberUpper = 1;
        private const int numberNonAlphaNumeric = 1;
        private const int numberNumeric = 2;
        private const int minPwdLength = 6;
        private const int maxPwdLength = Int32.MaxValue;

        //Number of hash iterations
        private const int iterations = 10002;

        //Salt length
        private const int saltSize = PWDTK.CDefaultSaltLength + 2;

        //This is the password policy that all passwords must adhere to, if the password doesn't meet the policy we save CPU processing time by not even bothering to calculate hash of a clearly incorrect password
        PWDTK.PasswordPolicy PwdPolicy = new PWDTK.PasswordPolicy(numberUpper, numberNonAlphaNumeric, numberNumeric, minPwdLength, maxPwdLength);


        public MainWindow()
        {
            InitializeComponent();
        }

        private void GetHashButton_Click(object sender, RoutedEventArgs e)
        {
            if (!PasswordMeetsPolicy(PasswordTextBox.Password, PwdPolicy)) return;

            //Get a random salt
            _salt = PWDTK.GetRandomSalt(saltSize);
            //Generate the hash value
            _hash = PWDTK.PasswordToHash(_salt, PasswordTextBox.Password, iterations);
            //store as a minimum salt, hash and the userID in the database now, I would also recomend storing iteration count as this will likely change in the future as hardware computes faster and so you may need to adjust iterations in the future
            CompareHashButton.IsEnabled = true;
            MessageBox.Show("Users Password Hash: " + PWDTK.HashBytesToHexString(_hash));
            MessageBox.Show("Hash stored, now try changing the text in the password field and hit the \"Compare\" button");
        }

        private void CompareHashButton_Click(object sender, RoutedEventArgs e)
        {
            if (!PasswordMeetsPolicy(PasswordTextBox.Password, PwdPolicy)) return;

            var stopW = new Stopwatch();
            stopW.Start();

            if (PWDTK.ComparePasswordToHash(_salt, PasswordTextBox.Password, _hash, iterations))
            {
                stopW.Stop();
                //Password hash matches stored hash allow entry into system and log details as per corporate audit logging
                MessageBox.Show("Password hash matches stored hash");
                MessageBox.Show("Creating the Hash and comparisson took a total of " + stopW.ElapsedMilliseconds.ToString() + " milliseconds, increase or decrease iterations to raise or lower this time");
            }
            else
            {
                stopW.Stop();
                //Password hash does NOT match stored hash, deny access and log details as per corporate audit logging
                MessageBox.Show("Password hash does NOT match stored hash");
                MessageBox.Show("Creating the Hash and comparisson took a total of " + stopW.ElapsedMilliseconds.ToString() + " milliseconds, increase or decrease iterations to raise or lower this time");
            }
        }


        private bool PasswordMeetsPolicy(String Password, PWDTK.PasswordPolicy PassPolicy)
        {
            PasswordPolicyException pwdEx = new PasswordPolicyException("");

            if (PWDTK.TryPasswordPolicyCompliance(Password, PassPolicy, ref pwdEx))
            {
                return true;
            }
            else
            {
                //Password does not comply with PasswordPolicy so we get the error message from the PasswordPolicyException to display to the user
                MessageBox.Show(pwdEx.Message);
                return false;
            }
        }
    }
}
