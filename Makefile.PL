use ExtUtils::MakeMaker;

WriteMakefile('NAME'         => 'Net::Hotline',
              'PMLIBDIRS'    => [ 'lib', 'lib/Net/', 'lib/Net/Hotline',
                                  'lib/Net/Hotline/Protocol' ],
              'VERSION_FROM' => 'lib/Net/Hotline.pm');
